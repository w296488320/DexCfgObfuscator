package com.hunter.dexcfgobf.string;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.objectweb.asm.TypePath;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Rebuilds modified library class files with a fresh ASM constant pool.
 *
 * <p>AGP's visitor pipeline deliberately seeds its writer from the original class, so removed LDC
 * and ConstantValue entries can remain as unreachable constant-pool data. D8/R8 drops those entries
 * for an APK, but a published AAR exposes {@code classes.jar} directly. This post-pass compacts only
 * classes actually modified by string encryption. Verification is deliberately artifact-wide: a
 * runtime String payload leaking from an excluded or generated class still fails the AAR gate,
 * while matching names/debug metadata remain whole-pool diagnostics unless strict mode is used.</p>
 */
public final class StringClassConstantPoolCompactor {
    private static final int CLASS_MAGIC = 0xCAFEBABE;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private StringClassConstantPoolCompactor() {
    }

    /** Compacts every currently modified class found directly or inside a nested project JAR. */
    public static int compactOutputs(Collection<File> roots, StringEncryptionContext context)
            throws IOException {
        if (context == null) throw new IOException("string encryption context is missing");
        int compacted = 0;
        for (Path artifact : collectArtifacts(roots)) {
            String name = artifact.getFileName().toString();
            if (name.endsWith(".class")) {
                if (compactClassFile(artifact, context)) compacted++;
            } else if (name.endsWith(".jar")) {
                compacted += compactJar(artifact, context);
            }
        }
        return compacted;
    }

    /** Scans JVM runtime String payloads and retains whole-pool matches as diagnostics. */
    public static VerificationResult verifyNoPlaintext(Collection<File> roots,
                                                        Set<String> expectedPlaintextHashes)
            throws IOException {
        return verifyNoPlaintext(roots, expectedPlaintextHashes, false);
    }

    /**
     * Scans every class/JAR output without retaining plaintext or matching hashes in the result.
     * By default only JVM runtime payloads gate the build; strict mode restores whole-pool gating.
     */
    public static VerificationResult verifyNoPlaintext(Collection<File> roots,
                                                        Set<String> expectedPlaintextHashes,
                                                        boolean strictWholeStringPool)
            throws IOException {
        Set<String> expected = normalizeHashes(expectedPlaintextHashes);
        MutableVerification result = new MutableVerification(expected.size());
        for (Path artifact : collectArtifacts(roots)) {
            String name = artifact.getFileName().toString();
            if (name.endsWith(".class")) {
                verifyClass(Files.readAllBytes(artifact), expected, result, artifact.toString());
            } else if (name.endsWith(".jar")) {
                verifyJar(artifact, expected, result);
            }
        }
        return result.freeze(strictWholeStringPool);
    }

    /** Stable content fingerprint over class entries only; JAR timestamps/compression are ignored. */
    public static String fingerprintOutputs(Collection<File> roots) throws IOException {
        List<FingerprintEntry> entries = new ArrayList<>();
        for (Path artifact : collectArtifacts(roots)) {
            String canonical = artifact.toFile().getCanonicalPath();
            String name = artifact.getFileName().toString();
            if (name.endsWith(".class")) {
                entries.add(new FingerprintEntry("class:" + canonical,
                        sha256Bytes(Files.newInputStream(artifact))));
            } else if (name.endsWith(".jar")) {
                try (JarFile jar = new JarFile(artifact.toFile())) {
                    for (JarEntry entry : classEntries(jar)) {
                        try (InputStream input = jar.getInputStream(entry)) {
                            entries.add(new FingerprintEntry("jar:" + canonical + "!/"
                                    + entry.getName(), sha256Bytes(input)));
                        }
                    }
                }
            }
        }
        if (entries.isEmpty()) {
            throw new IOException("class output roots contain no .class files or JAR class entries");
        }
        entries.sort(Comparator.comparing(item -> item.name));
        MessageDigest digest = newSha256();
        digest.update("library-class-outputs-v1".getBytes(StandardCharsets.UTF_8));
        for (FingerprintEntry entry : entries) {
            byte[] name = entry.name.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(name.length).array());
            digest.update(name);
            digest.update(entry.contentHash);
        }
        return toHex(digest.digest());
    }

    /** Complete pre-D8/R8 owner inventory from AGP scoped class roots. */
    public static Set<String> scanClassOwners(Collection<File> roots) throws IOException {
        Set<String> owners = new TreeSet<>();
        for (Path artifact : collectArtifacts(roots)) {
            String name = artifact.getFileName().toString();
            if (name.endsWith(".class")) {
                addClassOwner(Files.readAllBytes(artifact), owners, artifact.toString());
            } else if (name.endsWith(".jar")) {
                // AGP/Jetifier may rewrite an originally signed dependency without retaining a
                // valid JAR signature. The artifact is already a trusted Gradle classpath input;
                // inventory needs the actual class bytes, not legacy signature verification.
                try (JarFile jar = new JarFile(artifact.toFile(), false)) {
                    for (JarEntry entry : classEntries(jar)) {
                        try (InputStream input = jar.getInputStream(entry)) {
                            addClassOwner(readAll(input), owners,
                                    artifact + "!/" + entry.getName());
                        }
                    }
                }
            }
        }
        if (owners.isEmpty()) {
            throw new IOException("class output roots contain no .class files or JAR class entries");
        }
        return Collections.unmodifiableSet(owners);
    }

    private static void addClassOwner(byte[] bytes, Set<String> owners, String source)
            throws IOException {
        try {
            String owner = new ClassReader(bytes).getClassName();
            if (owner == null || owner.isEmpty()) {
                throw new IOException("JVM class owner is missing in " + source);
            }
            owners.add(owner);
        } catch (IllegalArgumentException failure) {
            throw new IOException("cannot read JVM class owner from " + source, failure);
        }
    }

    /**
     * Finds only calls emitted by transformed project classes into the generated bridge.
     *
     * <p>The bridge class itself is excluded: its String overload always delegates to the byte[]
     * overload, and counting that internal edge would incorrectly retain an otherwise unused
     * String carrier. Reading the class outputs makes this result stable across executed,
     * up-to-date, and build-cache-restored ASM tasks.</p>
     */
    public static BridgeUsage scanBridgeUsage(Collection<File> roots,
                                               String bridgeInternalName) throws IOException {
        String bridge = bridgeInternalName == null ? "" : bridgeInternalName.trim();
        if (bridge.isEmpty() || bridge.indexOf('.') >= 0) {
            throw new IOException("generated bridge internal name is missing/invalid");
        }
        MutableBridgeUsage usage = new MutableBridgeUsage();
        for (Path artifact : collectArtifacts(roots)) {
            String name = artifact.getFileName().toString();
            if (name.endsWith(".class")) {
                scanBridgeClass(Files.readAllBytes(artifact), bridge, usage,
                        artifact.toString());
            } else if (name.endsWith(".jar")) {
                try (JarFile jar = new JarFile(artifact.toFile())) {
                    for (JarEntry entry : classEntries(jar)) {
                        try (InputStream input = jar.getInputStream(entry)) {
                            scanBridgeClass(readAll(input), bridge, usage,
                                    artifact + "!/" + entry.getName());
                        }
                    }
                }
            }
        }
        if (usage.classesScanned == 0) {
            throw new IOException("class output roots contain no .class files or JAR class entries");
        }
        return usage.freeze();
    }

    private static void scanBridgeClass(byte[] bytes, String bridgeInternalName,
                                        MutableBridgeUsage usage, String source)
            throws IOException {
        try {
            ClassReader reader = new ClassReader(bytes);
            final boolean generatedBridge = bridgeInternalName.equals(reader.getClassName());
            usage.classesScanned++;
            if (generatedBridge) return;
            reader.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String methodName,
                                                    String methodDescriptor,
                                                    boolean isInterface) {
                            if (opcode != Opcodes.INVOKESTATIC
                                    || !bridgeInternalName.equals(owner)
                                    || !"decrypt".equals(methodName)) {
                                return;
                            }
                            if ("([B[B)Ljava/lang/String;".equals(methodDescriptor)) {
                                usage.byteCarrierCalled = true;
                            } else if (("(Ljava/lang/String;Ljava/lang/String;)"
                                    + "Ljava/lang/String;").equals(methodDescriptor)) {
                                usage.stringCarrierCalled = true;
                            }
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (RuntimeException failure) {
            throw new IOException("cannot scan generated bridge usage in " + source, failure);
        }
    }

    static byte[] compactClass(byte[] original) {
        ClassReader reader = new ClassReader(original);
        // Do not use ClassWriter(ClassReader,...): that constructor copies the original pool.
        ClassWriter writer = new ClassWriter(0);
        reader.accept(new RejectUnknownAttributesVisitor(writer, reader.getClassName()), 0);
        return writer.toByteArray();
    }

    private static boolean compactClassFile(Path classFile, StringEncryptionContext context)
            throws IOException {
        byte[] original = Files.readAllBytes(classFile);
        ClassReader reader = new ClassReader(original);
        if (!context.wasClassModified(reader.getClassName())) return false;
        byte[] compacted = compactClass(original);
        if (java.util.Arrays.equals(original, compacted)) return false;
        replaceBytes(classFile, compacted);
        return true;
    }

    private static int compactJar(Path jarPath, StringEncryptionContext context) throws IOException {
        Path parent = jarPath.toAbsolutePath().getParent();
        if (parent == null) throw new IOException("class JAR has no parent: " + jarPath);
        Path temporary = Files.createTempFile(parent, ".string-class-pool-", ".jar");
        int compacted = 0;
        boolean signed = false;
        try {
            try (JarFile input = new JarFile(jarPath.toFile());
                 JarOutputStream output = new JarOutputStream(Files.newOutputStream(temporary))) {
                Enumeration<JarEntry> entries = input.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (isSignatureEntry(entry.getName())) signed = true;
                    byte[] content;
                    try (InputStream stream = input.getInputStream(entry)) {
                        content = readAll(stream);
                    }
                    boolean changed = false;
                    if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                        ClassReader reader = new ClassReader(content);
                        if (context.wasClassModified(reader.getClassName())) {
                            byte[] replacement = compactClass(content);
                            if (!java.util.Arrays.equals(content, replacement)) {
                                content = replacement;
                                changed = true;
                                compacted++;
                            }
                        }
                    }
                    // Preserve all ZIP metadata for untouched resources/classes. A changed class
                    // cannot retain STORED size/CRC fields, so rebuild only that entry's metadata.
                    JarEntry emitted = changed ? new JarEntry(entry.getName()) : new JarEntry(entry);
                    if (changed) {
                        if (entry.getTime() >= 0L) emitted.setTime(entry.getTime());
                        if (entry.getComment() != null) emitted.setComment(entry.getComment());
                        if (entry.getExtra() != null) emitted.setExtra(entry.getExtra());
                    }
                    output.putNextEntry(emitted);
                    if (!entry.isDirectory()) output.write(content);
                    output.closeEntry();
                }
            }
            if (compacted == 0) return 0;
            if (signed) {
                throw new IOException("refusing to rewrite signed class JAR " + jarPath
                        + "; bytecode transformation invalidates META-INF signatures");
            }
            replaceFile(temporary, jarPath);
            return compacted;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void verifyJar(Path jarPath, Set<String> expected, MutableVerification result)
            throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            for (JarEntry entry : classEntries(jar)) {
                try (InputStream input = jar.getInputStream(entry)) {
                    verifyClass(readAll(input), expected, result,
                            jarPath + "!/" + entry.getName());
                }
            }
        }
    }

    private static void verifyClass(byte[] bytes, Set<String> expected,
                                    MutableVerification result, String source) throws IOException {
        scanWholeConstantPool(bytes, expected, result, source);
        try {
            new ClassReader(bytes).accept(new RuntimePayloadVisitor(expected, result, source), 0);
        } catch (RuntimeException failure) {
            throw new IOException("cannot semantically verify JVM class " + source, failure);
        }
    }

    private static void scanWholeConstantPool(byte[] bytes, Set<String> expected,
                                              MutableVerification result, String source)
            throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (input.readInt() != CLASS_MAGIC) {
                throw new IOException("invalid JVM class magic in " + source);
            }
            input.readUnsignedShort(); // minor
            input.readUnsignedShort(); // major
            int count = input.readUnsignedShort();
            result.classesScanned++;
            for (int index = 1; index < count; index++) {
                int tag = input.readUnsignedByte();
                switch (tag) {
                    case 1: {
                        String value = input.readUTF();
                        result.utf8EntriesScanned++;
                        String hash = StringPlaintextVerifier.sha256(value);
                        if (expected.contains(hash)) {
                            result.recordWholePool(hash);
                        }
                        break;
                    }
                    case 3: // Integer
                    case 4: // Float
                    case 9: // Fieldref
                    case 10: // Methodref
                    case 11: // InterfaceMethodref
                    case 12: // NameAndType
                    case 17: // Dynamic
                    case 18: // InvokeDynamic
                        skipFully(input, 4, source);
                        break;
                    case 5: // Long
                    case 6: // Double
                        skipFully(input, 8, source);
                        index++;
                        break;
                    case 7: // Class
                    case 8: // String
                    case 16: // MethodType
                    case 19: // Module
                    case 20: // Package
                        skipFully(input, 2, source);
                        break;
                    case 15: // MethodHandle
                        skipFully(input, 3, source);
                        break;
                    default:
                        throw new IOException("unsupported JVM constant-pool tag " + tag
                                + " in " + source);
                }
            }
        } catch (EOFException failure) {
            throw new IOException("truncated JVM constant pool in " + source, failure);
        }
    }

    private enum PayloadKind {
        LDC,
        STATIC_FIELD,
        ANNOTATION,
        CALL_SITE
    }

    /** ASM semantic scan deliberately ignores class/member/source/debug/record names. */
    private static final class RuntimePayloadVisitor extends ClassVisitor {
        private final Set<String> expected;
        private final MutableVerification result;
        private final String source;
        private final List<RecordObjectMethodsMetadata.Component> recordComponents =
                new ArrayList<>();
        private String className;
        private boolean recordClass;

        RuntimePayloadVisitor(Set<String> expected, MutableVerification result, String source) {
            super(Opcodes.ASM9);
            this.expected = expected;
            this.result = result;
            this.source = source;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            className = name;
            recordClass = (access & Opcodes.ACC_RECORD) != 0
                    && RecordObjectMethodsMetadata.RECORD_SUPER.equals(superName);
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            return annotationPayloadVisitor();
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath,
                                                     String descriptor, boolean visible) {
            return annotationPayloadVisitor();
        }

        @Override
        public void visitAttribute(Attribute attribute) {
            throw unknownAttribute("class", attribute);
        }

        @Override
        public RecordComponentVisitor visitRecordComponent(String name, String descriptor,
                                                            String signature) {
            recordComponents.add(new RecordObjectMethodsMetadata.Component(name, descriptor));
            return new RecordComponentVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotation(String annotationDescriptor,
                                                         boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath,
                                                             String annotationDescriptor,
                                                             boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public void visitAttribute(Attribute attribute) {
                    throw unknownAttribute("record component", attribute);
                }
            };
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor,
                                       String signature, Object value) {
            if ((access & Opcodes.ACC_STATIC) != 0 && "Ljava/lang/String;".equals(descriptor)
                    && value instanceof String) {
                recordRuntime((String) value, PayloadKind.STATIC_FIELD);
            }
            return new FieldVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotation(String annotationDescriptor,
                                                         boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath,
                                                             String annotationDescriptor,
                                                             boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public void visitAttribute(Attribute attribute) {
                    throw unknownAttribute("field", attribute);
                }
            };
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotationDefault() {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitAnnotation(String annotationDescriptor,
                                                         boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath,
                                                             String annotationDescriptor,
                                                             boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitParameterAnnotation(int parameter,
                                                                  String annotationDescriptor,
                                                                  boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitInsnAnnotation(int typeRef, TypePath typePath,
                                                             String annotationDescriptor,
                                                             boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitTryCatchAnnotation(int typeRef, TypePath typePath,
                                                                 String annotationDescriptor,
                                                                 boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitLocalVariableAnnotation(int typeRef,
                                                                      TypePath typePath,
                                                                      Label[] start, Label[] end,
                                                                      int[] index,
                                                                      String annotationDescriptor,
                                                                      boolean visible) {
                    return annotationPayloadVisitor();
                }

                @Override
                public void visitLdcInsn(Object value) {
                    if (value instanceof String) {
                        recordRuntime((String) value, PayloadKind.LDC);
                    } else if (value instanceof ConstantDynamic) {
                        scanConstantDynamic((ConstantDynamic) value);
                    }
                }

                @Override
                public void visitInvokeDynamicInsn(String invokeDynamicName,
                                                   String invokeDynamicDescriptor,
                                                   Handle bootstrapMethodHandle,
                                                   Object... bootstrapMethodArguments) {
                    for (int i = 0; i < bootstrapMethodArguments.length; i++) {
                        if (RecordObjectMethodsMetadata.isStructuralComponentNames(
                                recordClass, className, recordComponents, name, descriptor,
                                invokeDynamicName, invokeDynamicDescriptor,
                                bootstrapMethodHandle, bootstrapMethodArguments, i)) {
                            continue;
                        }
                        scanBootstrapArgument(bootstrapMethodArguments[i]);
                    }
                    if (invokeDynamicName != null && !invokeDynamicName.isEmpty()
                            && !CompilerCallSiteMetadata.isStructuralInvokeDynamicName(
                            recordClass, className, recordComponents, name, descriptor,
                            invokeDynamicName, invokeDynamicDescriptor,
                            bootstrapMethodHandle, bootstrapMethodArguments)) {
                        recordRuntime(invokeDynamicName, PayloadKind.CALL_SITE);
                    }
                }

                @Override
                public void visitAttribute(Attribute attribute) {
                    throw unknownAttribute(attribute != null && attribute.isCodeAttribute()
                            ? "code" : "method", attribute);
                }
            };
        }

        private AnnotationVisitor annotationPayloadVisitor() {
            return new AnnotationVisitor(Opcodes.ASM9) {
                @Override
                public void visit(String name, Object value) {
                    if (value instanceof String) {
                        recordRuntime((String) value, PayloadKind.ANNOTATION);
                    }
                }

                @Override
                public AnnotationVisitor visitAnnotation(String name, String descriptor) {
                    return annotationPayloadVisitor();
                }

                @Override
                public AnnotationVisitor visitArray(String name) {
                    return annotationPayloadVisitor();
                }
            };
        }

        private void scanBootstrapArgument(Object argument) {
            if (argument instanceof String) {
                recordRuntime((String) argument, PayloadKind.CALL_SITE);
            } else if (argument instanceof ConstantDynamic) {
                scanConstantDynamic((ConstantDynamic) argument);
            }
        }

        private void scanConstantDynamic(ConstantDynamic dynamic) {
            CompilerCallSiteMetadata.scanConstantDynamic(dynamic,
                    value -> recordRuntime(value, PayloadKind.CALL_SITE),
                    name -> {
                        if (name != null && !name.isEmpty()) {
                            recordRuntime(name, PayloadKind.CALL_SITE);
                        }
                    });
        }

        private void recordRuntime(String value, PayloadKind kind) {
            result.recordRuntime(value, kind, expected);
        }

        private IllegalArgumentException unknownAttribute(String location, Attribute attribute) {
            String type = attribute == null ? "<null>" : attribute.type;
            return new IllegalArgumentException("cannot safely verify " + source + ": unknown "
                    + location + " attribute " + type + " may contain hidden JVM payloads");
        }
    }

    private static List<Path> collectArtifacts(Collection<File> roots) throws IOException {
        if (roots == null || roots.isEmpty()) {
            throw new IOException("library ASM transform produced no class outputs");
        }
        Set<String> seen = new HashSet<>();
        List<Path> artifacts = new ArrayList<>();
        for (File root : roots) {
            if (root == null || !root.exists()) continue;
            if (root.isDirectory()) {
                List<Path> nested = new ArrayList<>();
                try (java.util.stream.Stream<Path> paths = Files.walk(root.toPath())) {
                    paths.filter(Files::isRegularFile)
                            .filter(StringClassConstantPoolCompactor::isClassOrJar)
                            .forEach(nested::add);
                }
                nested.sort(Comparator.comparing(path -> path.toAbsolutePath().normalize().toString()));
                for (Path path : nested) addArtifact(path, seen, artifacts);
            } else if (root.isFile() && isClassOrJar(root.toPath())) {
                addArtifact(root.toPath(), seen, artifacts);
            }
        }
        artifacts.sort(Comparator.comparing(path -> path.toAbsolutePath().normalize().toString()));
        return artifacts;
    }

    private static void addArtifact(Path path, Set<String> seen, List<Path> artifacts)
            throws IOException {
        String canonical = path.toFile().getCanonicalPath();
        if (seen.add(canonical)) artifacts.add(path);
    }

    private static boolean isClassOrJar(Path path) {
        String name = path.getFileName().toString();
        return name.endsWith(".class") || name.endsWith(".jar");
    }

    private static List<JarEntry> classEntries(JarFile jar) {
        List<JarEntry> entries = new ArrayList<>();
        Enumeration<JarEntry> enumeration = jar.entries();
        while (enumeration.hasMoreElements()) {
            JarEntry entry = enumeration.nextElement();
            if (!entry.isDirectory() && entry.getName().endsWith(".class")) entries.add(entry);
        }
        entries.sort(Comparator.comparing(JarEntry::getName));
        return entries;
    }

    private static boolean isSignatureEntry(String name) {
        if (name == null) return false;
        String upper = name.toUpperCase(Locale.ROOT);
        if (!upper.startsWith("META-INF/")) return false;
        String leaf = upper.substring("META-INF/".length());
        return !leaf.contains("/") && (leaf.endsWith(".SF") || leaf.endsWith(".RSA")
                || leaf.endsWith(".DSA") || leaf.endsWith(".EC") || leaf.startsWith("SIG-"));
    }

    private static Set<String> normalizeHashes(Set<String> hashes) throws IOException {
        if (hashes == null || hashes.isEmpty()) return Collections.emptySet();
        Set<String> normalized = new TreeSet<>();
        for (String hash : hashes) {
            String value = hash == null ? "" : hash.trim().toLowerCase(Locale.ROOT);
            if (!value.matches("[0-9a-f]{64}")) {
                throw new IOException("invalid protected plaintext SHA-256 evidence");
            }
            normalized.add(value);
        }
        return normalized;
    }

    private static void skipFully(DataInputStream input, int count, String source)
            throws IOException {
        int remaining = count;
        while (remaining > 0) {
            int skipped = input.skipBytes(remaining);
            if (skipped <= 0) throw new EOFException("truncated JVM constant pool in " + source);
            remaining -= skipped;
        }
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[16 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (count > 0) output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static byte[] sha256Bytes(InputStream input) throws IOException {
        try (InputStream stream = input) {
            MessageDigest digest = newSha256();
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = stream.read(buffer)) != -1) {
                if (count > 0) digest.update(buffer, 0, count);
            }
            return digest.digest();
        }
    }

    public static final class BridgeUsage {
        public final int classesScanned;
        public final boolean byteCarrierCalled;
        public final boolean stringCarrierCalled;

        private BridgeUsage(int classesScanned, boolean byteCarrierCalled,
                            boolean stringCarrierCalled) {
            this.classesScanned = classesScanned;
            this.byteCarrierCalled = byteCarrierCalled;
            this.stringCarrierCalled = stringCarrierCalled;
        }
    }

    private static final class MutableBridgeUsage {
        int classesScanned;
        boolean byteCarrierCalled;
        boolean stringCarrierCalled;

        BridgeUsage freeze() {
            return new BridgeUsage(classesScanned, byteCarrierCalled, stringCarrierCalled);
        }
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String toHex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            int unsigned = item & 0xff;
            result.append(HEX[unsigned >>> 4]).append(HEX[unsigned & 0x0f]);
        }
        return result.toString();
    }

    private static void replaceBytes(Path target, byte[] content) throws IOException {
        Path parent = target.toAbsolutePath().getParent();
        if (parent == null) throw new IOException("class file has no parent: " + target);
        Path temporary = Files.createTempFile(parent, ".string-class-pool-", ".class");
        try {
            Files.write(temporary, content);
            replaceFile(temporary, target);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void replaceFile(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Unknown attributes can embed old constant-pool indexes; copying them into a fresh pool is unsafe. */
    private static final class RejectUnknownAttributesVisitor extends ClassVisitor {
        private final String owner;

        RejectUnknownAttributesVisitor(ClassVisitor delegate, String owner) {
            super(Opcodes.ASM9, delegate);
            this.owner = owner;
        }

        @Override
        public void visitAttribute(Attribute attribute) {
            throw unsupportedAttribute("class", attribute);
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor,
                                       String signature, Object value) {
            FieldVisitor delegate = super.visitField(access, name, descriptor, signature, value);
            return new FieldVisitor(Opcodes.ASM9, delegate) {
                @Override
                public void visitAttribute(Attribute attribute) {
                    throw unsupportedAttribute("field", attribute);
                }
            };
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature,
                    exceptions);
            return new MethodVisitor(Opcodes.ASM9, delegate) {
                @Override
                public void visitAttribute(Attribute attribute) {
                    throw unsupportedAttribute(attribute != null && attribute.isCodeAttribute()
                            ? "code" : "method", attribute);
                }
            };
        }

        @Override
        public RecordComponentVisitor visitRecordComponent(String name, String descriptor,
                                                            String signature) {
            RecordComponentVisitor delegate = super.visitRecordComponent(name, descriptor,
                    signature);
            return new RecordComponentVisitor(Opcodes.ASM9, delegate) {
                @Override
                public void visitAttribute(Attribute attribute) {
                    throw unsupportedAttribute("record component", attribute);
                }
            };
        }

        private IllegalArgumentException unsupportedAttribute(String location,
                                                               Attribute attribute) {
            String type = attribute == null ? "<null>" : attribute.type;
            return new IllegalArgumentException("cannot safely compact " + owner + ": unknown "
                    + location + " attribute " + type
                    + " may contain stale JVM constant-pool indexes");
        }
    }

    private static final class MutableVerification {
        final int plaintextHashesTracked;
        final Set<String> runtimeMatchedHashes = new LinkedHashSet<>();
        final Set<String> wholePoolMatchedHashes = new LinkedHashSet<>();
        int classesScanned;
        int utf8EntriesScanned;
        int runtimeLeakOccurrences;
        int wholePoolCollisionOccurrences;
        int ldcStringValuesScanned;
        int staticStringValuesScanned;
        int annotationStringValuesScanned;
        int callSiteStringValuesScanned;

        MutableVerification(int plaintextHashesTracked) {
            this.plaintextHashesTracked = plaintextHashesTracked;
        }

        void recordWholePool(String hash) {
            wholePoolCollisionOccurrences++;
            wholePoolMatchedHashes.add(hash);
        }

        void recordRuntime(String value, PayloadKind kind, Set<String> expected) {
            switch (kind) {
                case LDC: ldcStringValuesScanned++; break;
                case STATIC_FIELD: staticStringValuesScanned++; break;
                case ANNOTATION: annotationStringValuesScanned++; break;
                case CALL_SITE: callSiteStringValuesScanned++; break;
                default: throw new IllegalStateException("unknown JVM String payload kind");
            }
            String hash = StringPlaintextVerifier.sha256(value);
            if (expected.contains(hash)) {
                runtimeLeakOccurrences++;
                runtimeMatchedHashes.add(hash);
            }
        }

        VerificationResult freeze(boolean strictWholeStringPool) {
            int effectiveLeaks = strictWholeStringPool
                    ? wholePoolMatchedHashes.size() : runtimeMatchedHashes.size();
            int effectiveOccurrences = strictWholeStringPool
                    ? wholePoolCollisionOccurrences : runtimeLeakOccurrences;
            return new VerificationResult(classesScanned, utf8EntriesScanned,
                    plaintextHashesTracked, effectiveLeaks, effectiveOccurrences,
                    runtimeMatchedHashes.size(), runtimeLeakOccurrences,
                    wholePoolMatchedHashes.size(), wholePoolCollisionOccurrences,
                    ldcStringValuesScanned, staticStringValuesScanned,
                    annotationStringValuesScanned, callSiteStringValuesScanned,
                    strictWholeStringPool);
        }
    }

    public static final class VerificationResult {
        public final int classesScanned;
        public final int utf8EntriesScanned;
        public final int plaintextHashesTracked;
        /** Effective gate result: runtime payloads by default, whole pool in strict mode. */
        public final int plaintextLeaks;
        public final int plaintextLeakOccurrences;
        public final int runtimePlaintextLeaks;
        public final int runtimePlaintextLeakOccurrences;
        public final int wholePoolPlaintextCollisions;
        public final int wholePoolPlaintextCollisionOccurrences;
        public final int ldcStringValuesScanned;
        public final int staticStringValuesScanned;
        public final int annotationStringValuesScanned;
        public final int callSiteStringValuesScanned;
        public final boolean strictWholeStringPool;

        VerificationResult(int classesScanned, int utf8EntriesScanned,
                           int plaintextHashesTracked, int plaintextLeaks,
                           int plaintextLeakOccurrences,
                           int runtimePlaintextLeaks,
                           int runtimePlaintextLeakOccurrences,
                           int wholePoolPlaintextCollisions,
                           int wholePoolPlaintextCollisionOccurrences,
                           int ldcStringValuesScanned,
                           int staticStringValuesScanned,
                           int annotationStringValuesScanned,
                           int callSiteStringValuesScanned,
                           boolean strictWholeStringPool) {
            this.classesScanned = classesScanned;
            this.utf8EntriesScanned = utf8EntriesScanned;
            this.plaintextHashesTracked = plaintextHashesTracked;
            this.plaintextLeaks = plaintextLeaks;
            this.plaintextLeakOccurrences = plaintextLeakOccurrences;
            this.runtimePlaintextLeaks = runtimePlaintextLeaks;
            this.runtimePlaintextLeakOccurrences = runtimePlaintextLeakOccurrences;
            this.wholePoolPlaintextCollisions = wholePoolPlaintextCollisions;
            this.wholePoolPlaintextCollisionOccurrences =
                    wholePoolPlaintextCollisionOccurrences;
            this.ldcStringValuesScanned = ldcStringValuesScanned;
            this.staticStringValuesScanned = staticStringValuesScanned;
            this.annotationStringValuesScanned = annotationStringValuesScanned;
            this.callSiteStringValuesScanned = callSiteStringValuesScanned;
            this.strictWholeStringPool = strictWholeStringPool;
        }
    }

    private static final class FingerprintEntry {
        final String name;
        final byte[] contentHash;

        FingerprintEntry(String name, byte[] contentHash) {
            this.name = name;
            this.contentHash = contentHash;
        }
    }
}
