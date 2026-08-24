package com.hunter.dexcfgobf.string;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class GenerateStringProtectionRulesR8Test {
    private static final String MARKER = "lab.Bridge$ExactStringSite";
    private static final String MARKER_DESCRIPTOR = "Llab/Bridge$ExactStringSite;";

    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void minimalRuleProtectsLiveMethodAndConstructorWithoutRetainingMarkerMetadata()
            throws Exception {
        Path root = temporary.newFolder("r8-marker").toPath();
        Path sourceRoot = Files.createDirectories(root.resolve("src/lab"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        Path bridge = sourceRoot.resolve("Bridge.java");
        Path sample = sourceRoot.resolve("Sample.java");
        Files.writeString(bridge, "package lab;\n"
                + "public final class Bridge {\n"
                + "  @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.CLASS)\n"
                + "  @java.lang.annotation.Target({java.lang.annotation.ElementType.METHOD, "
                + "java.lang.annotation.ElementType.CONSTRUCTOR})\n"
                + "  public @interface ExactStringSite {}\n"
                + "}\n", StandardCharsets.UTF_8);
        Files.writeString(sample, "package lab;\n"
                + "public final class Sample {\n"
                + "  private final String value;\n"
                + "  @Bridge.ExactStringSite public Sample(String value) { "
                + "this.value = value + \"!\"; }\n"
                + "  @Bridge.ExactStringSite public Sample(String value, int dead) { "
                + "this.value = value + dead; }\n"
                + "  @Bridge.ExactStringSite public static String markedLive(String value) { "
                + "return value + \"m\"; }\n"
                + "  @Bridge.ExactStringSite public static String markedDead(String value) { "
                + "return value + \"d\"; }\n"
                + "  public static String unmarkedLive(String value) { return value + \"u\"; }\n"
                + "  public String get() { return value; }\n"
                + "  public static String entry(String value) { return new Sample(value).get() "
                + "+ markedLive(value) + unmarkedLive(value); }\n"
                + "}\n", StandardCharsets.UTF_8);
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull("R8 rule contract test requires a JDK", compiler);
        assertEquals(0, compiler.run(null, null, null, "-g:none", "-d", classes.toString(),
                bridge.toString(), sample.toString()));

        Path input = root.resolve("input.jar");
        writeJar(classes, input);
        Path output = root.resolve("output.jar");
        Path mapping = root.resolve("mapping.txt");
        Path usage = root.resolve("usage.txt");
        Path seeds = root.resolve("seeds.txt");
        Path rules = root.resolve("rules.pro");
        Files.writeString(rules,
                "-keep,allowoptimization,allowobfuscation class lab.Sample {\n"
                        + "    public static java.lang.String entry(java.lang.String);\n"
                        + "}\n"
                        + GenerateStringProtectionRulesTask.renderRules(MARKER)
                        + "-dontwarn **\n"
                        + "-printusage " + usage + "\n"
                        + "-printseeds " + seeds + "\n",
                StandardCharsets.UTF_8);

        List<String> command = new ArrayList<>();
        command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("com.android.tools.r8.R8");
        command.add("--release");
        command.add("--classfile");
        command.add("--output");
        command.add(output.toString());
        command.add("--lib");
        command.add(System.getProperty("java.home"));
        command.add("--pg-conf");
        command.add(rules.toString());
        command.add("--pg-map-output");
        command.add(mapping.toString());
        command.add(input.toString());
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        assertTrue("R8 timed out", process.waitFor(60, TimeUnit.SECONDS));
        String processOutput = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        assertEquals(processOutput, 0, process.exitValue());

        String map = Files.readString(mapping);
        String removed = Files.readString(usage);
        String kept = Files.readString(seeds);
        String finalOwner = capture(map, "(?m)^lab\\.Sample -> ([^:]+):$");
        String finalMethod = capture(map,
                "(?m)^\\s+.*java\\.lang\\.String markedLive\\(java\\.lang\\.String\\)"
                        + ".* -> (\\S+)$");
        assertTrue("live marked method must be a seed", kept.contains(
                "lab.Sample: java.lang.String markedLive(java.lang.String)"));
        assertTrue("live marked constructor must be a seed", kept.contains(
                "lab.Sample: Sample(java.lang.String)"));
        assertTrue("dead marked method remains shrinkable", removed.contains(
                "java.lang.String markedDead(java.lang.String)"));
        assertTrue("dead marked constructor remains shrinkable", removed.contains(
                "void <init>(java.lang.String,int)"));

        try (JarFile jar = new JarFile(output.toFile())) {
            assertFalse("marker type must be removable after R8 rule matching",
                    jar.stream().anyMatch(entry -> entry.getName().endsWith(
                            "Bridge$ExactStringSite.class")));
            JarEntry ownerEntry = jar.getJarEntry(finalOwner.replace('.', '/') + ".class");
            assertNotNull("mapped final owner missing", ownerEntry);
            ClassNode finalClass = new ClassNode();
            try (InputStream stream = jar.getInputStream(ownerEntry)) {
                new ClassReader(stream.readAllBytes()).accept(finalClass, 0);
            }
            assertNotNull("marked method boundary was optimized away",
                    method(finalClass, finalMethod, "(Ljava/lang/String;)Ljava/lang/String;"));
            assertNotNull("marked constructor boundary/prototype was rewritten",
                    method(finalClass, "<init>", "(Ljava/lang/String;)V"));
            assertFalse("CLASS marker attribute need not survive final output",
                    containsAnnotation(finalClass, MARKER_DESCRIPTOR));
        }
    }

    private static String capture(String value, String expression) {
        Matcher matcher = Pattern.compile(expression).matcher(value);
        assertTrue("missing pattern " + expression + " in:\n" + value, matcher.find());
        return matcher.group(1);
    }

    private static MethodNode method(ClassNode owner, String name, String descriptor) {
        for (MethodNode method : owner.methods) {
            if (name.equals(method.name) && descriptor.equals(method.desc)) return method;
        }
        return null;
    }

    private static boolean containsAnnotation(ClassNode owner, String descriptor) {
        for (MethodNode method : owner.methods) {
            if (containsAnnotation(method.visibleAnnotations, descriptor)
                    || containsAnnotation(method.invisibleAnnotations, descriptor)) return true;
        }
        return false;
    }

    private static boolean containsAnnotation(List<AnnotationNode> annotations,
                                              String descriptor) {
        if (annotations == null) return false;
        for (AnnotationNode annotation : annotations) {
            if (descriptor.equals(annotation.desc)) return true;
        }
        return false;
    }

    private static void writeJar(Path classes, Path output) throws Exception {
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output));
             java.util.stream.Stream<Path> paths = Files.walk(classes)) {
            for (Path path : (Iterable<Path>) paths.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(Path::toString))::iterator) {
                JarEntry entry = new JarEntry(classes.relativize(path).toString()
                        .replace(File.separatorChar, '/'));
                jar.putNextEntry(entry);
                Files.copy(path, jar);
                jar.closeEntry();
            }
        }
    }
}
