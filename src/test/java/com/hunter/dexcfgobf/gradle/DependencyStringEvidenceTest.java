package com.hunter.dexcfgobf.gradle;

import com.hunter.dexcfgobf.BuildEvidenceStore;
import com.hunter.dexcfgobf.ObfuscatorStats;
import com.hunter.dexcfgobf.string.StringClassConstantPoolCompactor;
import com.hunter.dexcfgobf.string.StringPlaintextVerifier;

import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class DependencyStringEvidenceTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void acceptsOnlyFullMemberScopedEvidenceBoundToCurrentTransformOutputs()
            throws Exception {
        Fixture fixture = fixture("FULL", true, 0);

        DexCfgObfuscatorPlugin.DependencyStringEvidence loaded =
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(
                        fixture.evidence, Collections.singletonList(fixture.outputs),
                        "dependency-transform", "release", ":feature");

        assertEquals(":feature", loaded.getProjectPath());
        assertEquals(1, loaded.getStats().stringConstantsEncrypted);
        assertEquals(Collections.singleton(fixture.hash),
                loaded.getScope().getPlaintextHashes());
        assertEquals(Collections.singleton(fixture.hash),
                loaded.getScope().getPlaintextHashesByOriginalMethod().get(
                        "fixture/Dependency->value()Ljava/lang/String;"));
    }

    @Test
    public void rejectsStalePartialOrUnverifiedDependencyEvidence() throws Exception {
        Fixture stale = fixture("FULL", true, 0);
        Files.write(new File(stale.outputs, "fixture/Dependency.class").toPath(),
                new byte[]{1}, java.nio.file.StandardOpenOption.APPEND);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(stale.evidence,
                        Collections.singletonList(stale.outputs), "dependency-transform",
                        "release", ":feature"));

        Fixture partial = fixture("PARTIAL_OR_FULL", true, 0);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(partial.evidence,
                        Collections.singletonList(partial.outputs), "dependency-transform",
                        "release", ":feature"));
        DexCfgObfuscatorPlugin.DependencyStringEvidence knownPartial =
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(partial.evidence,
                        Collections.singletonList(partial.outputs), "dependency-transform",
                        "debug", ":feature", false);
        assertEquals("PARTIAL_OR_FULL", knownPartial.getStats().stringCoverageStatus);

        Fixture unverified = fixture("FULL", false, 0);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(unverified.evidence,
                        Collections.singletonList(unverified.outputs), "dependency-transform",
                        "release", ":feature"));

        Fixture leaked = fixture("FULL", true, 1);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(leaked.evidence,
                        Collections.singletonList(leaked.outputs), "dependency-transform",
                        "release", ":feature"));

        Fixture wrongDigest = fixture("FULL", true, 0);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(wrongDigest.evidence,
                        Collections.singletonList(wrongDigest.outputs), "different-transform",
                        "release", ":feature"));
    }

    @Test
    public void rejectsEmptyOutputsAndOwnerMemberMismatchBeforeAggregation() throws Exception {
        File emptyOutputs = temporary.newFolder();
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(
                        new File(emptyOutputs, "missing.evidence"),
                        Collections.singletonList(emptyOutputs), "dependency-transform",
                        "release", ":empty"));

        File root = temporary.newFolder();
        File outputs = new File(root, "transform");
        File classFile = new File(outputs, "fixture/Dependency.class");
        assertTrue(classFile.getParentFile().mkdirs());
        Files.write(classFile.toPath(), dependencyClass());
        String fingerprint = StringClassConstantPoolCompactor.fingerprintOutputs(
                Collections.singletonList(outputs));
        File evidence = BuildEvidenceStore.stringEvidenceFile(new File(root, "evidence"),
                "release-library-class-pool");
        String firstHash = StringPlaintextVerifier.sha256("first protected value");
        String secondHash = StringPlaintextVerifier.sha256("second protected value");
        Set<String> hashes = new LinkedHashSet<>(Arrays.asList(firstHash, secondHash));
        Map<String, Set<String>> classes = new LinkedHashMap<>();
        classes.put("fixture/First", Collections.singleton(firstHash));
        classes.put("fixture/Second", Collections.singleton(secondHash));
        Map<String, Set<String>> methods = new LinkedHashMap<>();
        // Global unions are complete, but both hashes are attributed to the wrong owner.
        methods.put("fixture/First->value()Ljava/lang/String;",
                Collections.singleton(secondHash));
        methods.put("fixture/Second->value()Ljava/lang/String;",
                Collections.singleton(firstHash));
        ObfuscatorStats stats = validStats(fingerprint, "FULL", true, 0);
        stats.stringConstantsEncrypted = 2;
        stats.stringClassesVisited = 2;
        stats.stringClassesModified = 2;
        BuildEvidenceStore.writeString(evidence, fingerprint, "dependency-transform", stats,
                hashes, classes, methods, Collections.emptyMap());

        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.readDependencyStringEvidence(evidence,
                        Collections.singletonList(outputs), "dependency-transform",
                        "release", ":mismatched"));
    }

    @Test
    public void validatesAbsoluteExistingUniqueDependencyProjectPaths() {
        Project root = ProjectBuilder.builder().withName("root").build();
        Project app = ProjectBuilder.builder().withName("app").withParent(root).build();
        Project library = ProjectBuilder.builder().withName("feature").withParent(root).build();

        assertEquals(Collections.singletonList(library.getPath()),
                DexCfgObfuscatorPlugin.validateDependencyEvidenceProjects(app,
                        Collections.singletonList(":feature")));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.validateDependencyEvidenceProjects(app,
                        Collections.singletonList("feature")));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.validateDependencyEvidenceProjects(app,
                        Collections.singletonList(":missing")));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.validateDependencyEvidenceProjects(app,
                        Collections.singletonList(":app")));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.validateDependencyEvidenceProjects(app,
                        Arrays.asList(":feature", ":feature")));
    }

    @Test
    public void rejectsMissingOrPreMinifiedDependencyVariantDescriptor() {
        Project project = ProjectBuilder.builder().withName("feature").build();
        Task task = project.getTasks().create("compactReleaseLibraryStringConstantPools");
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.requireUnminifiedDependencyEvidenceTask(
                        task, "release", ":feature"));

        task.getExtensions().getExtraProperties().set(
                "dexCfgObfuscatorLibraryVariantMinified", true);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.requireUnminifiedDependencyEvidenceTask(
                        task, "release", ":feature"));

        task.getExtensions().getExtraProperties().set(
                "dexCfgObfuscatorLibraryVariantMinified", false);
        DexCfgObfuscatorPlugin.requireUnminifiedDependencyEvidenceTask(
                task, "release", ":feature");
    }

    private Fixture fixture(String coverage, boolean verified, int leaks) throws Exception {
        File root = temporary.newFolder();
        File outputs = new File(root, "transform");
        File classFile = new File(outputs, "fixture/Dependency.class");
        assertTrue(classFile.getParentFile().mkdirs());
        Files.write(classFile.toPath(), dependencyClass());
        String fingerprint = StringClassConstantPoolCompactor.fingerprintOutputs(
                Collections.singletonList(outputs));
        File evidence = BuildEvidenceStore.stringEvidenceFile(new File(root, "evidence"),
                "release-library-class-pool");
        String hash = StringPlaintextVerifier.sha256("dependency protected value");
        Set<String> hashes = Collections.singleton(hash);
        Map<String, Set<String>> classes = Collections.singletonMap("fixture/Dependency", hashes);
        Map<String, Set<String>> methods = new LinkedHashMap<>();
        methods.put("fixture/Dependency->value()Ljava/lang/String;", hashes);

        ObfuscatorStats stats = validStats(fingerprint, coverage, verified, leaks);
        BuildEvidenceStore.writeString(evidence, fingerprint, "dependency-transform", stats,
                hashes, classes, methods, Collections.emptyMap());
        return new Fixture(outputs, evidence, hash);
    }

    private static ObfuscatorStats validStats(String fingerprint, String coverage,
                                               boolean verified, int leaks) {
        ObfuscatorStats stats = new ObfuscatorStats();
        stats.stringEncryptionEnabled = true;
        stats.stringEncryptionMode = "BYTES";
        stats.stringCoverageStatus = coverage;
        stats.stringClassesVisited = 1;
        stats.stringClassesModified = 1;
        stats.stringConstantsEncrypted = 1;
        stats.stringPlaintextVerified = verified;
        stats.stringPlaintextLeaks = leaks;
        stats.stringPlaintextLeakOccurrences = leaks;
        stats.stringPlaintextGateMode = "LIBRARY_JVM_RUNTIME_PAYLOAD";
        stats.artifactFingerprint = fingerprint;
        stats.stringTransformDigest = "dependency-transform";
        return stats;
    }

    private static byte[] dependencyClass() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixture/Dependency", null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn("ciphertext placeholder");
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static final class Fixture {
        final File outputs;
        final File evidence;
        final String hash;

        Fixture(File outputs, File evidence, String hash) {
            this.outputs = outputs;
            this.evidence = evidence;
            this.hash = hash;
        }
    }
}
