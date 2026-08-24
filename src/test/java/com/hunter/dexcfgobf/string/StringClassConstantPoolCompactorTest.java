package com.hunter.dexcfgobf.string;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class StringClassConstantPoolCompactorTest {
    private static final String UNUSED_SECRET = "UNUSED_LIBRARY_SECRET_734921";
    private static final String LDC_SECRET = "LDC_LIBRARY_SECRET_194357";
    private static final String ANNOTATION_SECRET = "ANNOTATION_LIBRARY_SECRET_620813";
    private static final String NESTED_ANNOTATION_SECRET =
            "NESTED_ANNOTATION_LIBRARY_SECRET_975321";
    private static final String BOOTSTRAP_SECRET = "BOOTSTRAP_LIBRARY_SECRET_731905";
    private static final String CONSTANT_DYNAMIC_SECRET = "CONDY_LIBRARY_SECRET_810247";
    private static final String INVOKE_DYNAMIC_NAME_SECRET =
            "INDY_NAME_LIBRARY_SECRET_483921";
    private static final String CONSTANT_DYNAMIC_NAME_SECRET =
            "CONDY_NAME_LIBRARY_SECRET_672143";

    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void freshWriterDropsUnreachableConstantPoolEntries() {
        byte[] original = classWithUnusedConstant("fixture/library/Sample");
        assertTrue(contains(original, UNUSED_SECRET));

        byte[] compacted = StringClassConstantPoolCompactor.compactClass(original);

        assertFalse(contains(compacted, UNUSED_SECRET));
        assertEquals("fixture/library/Sample", new ClassReader(compacted).getClassName());
    }

    @Test
    public void discoversExactBridgeCarrierUsageFromDirectoryAndJarArtifacts()
            throws Exception {
        String bridge = "fixture/library/GeneratedBridge";
        File root = temporary.newFolder("bridge-usage");
        File bridgeClass = new File(root, bridge + ".class");
        assertTrue(bridgeClass.getParentFile().mkdirs());
        // The generated String overload delegates to byte[], but the bridge's internal edge is not
        // an external carrier site and must not keep either overload alive by itself.
        Files.write(bridgeClass.toPath(), classWithBridgeCall(bridge, bridge,
                "([B[B)Ljava/lang/String;"));
        StringClassConstantPoolCompactor.BridgeUsage unused =
                StringClassConstantPoolCompactor.scanBridgeUsage(
                        Collections.singletonList(root), bridge);
        assertEquals(1, unused.classesScanned);
        assertFalse(unused.byteCarrierCalled);
        assertFalse(unused.stringCarrierCalled);

        File byteCaller = new File(root, "fixture/library/ByteCaller.class");
        Files.write(byteCaller.toPath(), classWithBridgeCall(
                "fixture/library/ByteCaller", bridge, "([B[B)Ljava/lang/String;"));
        StringClassConstantPoolCompactor.BridgeUsage bytes =
                StringClassConstantPoolCompactor.scanBridgeUsage(
                        Collections.singletonList(root), bridge);
        assertTrue(bytes.byteCarrierCalled);
        assertFalse(bytes.stringCarrierCalled);

        StringEncryptionContext context = StringEncryptionContext.create(null, null, null,
                Collections.singletonList("fixture.library"), Collections.emptyList(),
                bridge.replace('/', '.'), StringEncryptionMode.BYTES,
                17L, 16_384, false, true, false, true);
        assertEquals(Collections.singleton(
                        bridge + "->decrypt([B[B)Ljava/lang/String;"),
                context.discoverRequiredDecryptorOriginalMethodKeys(
                        Collections.singletonList(root)));

        File jar = new File(root, "nested/string-caller.jar");
        assertTrue(jar.getParentFile().mkdirs());
        writeJar(jar, classWithBridgeCall("fixture/library/StringCaller", bridge,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"), false);
        StringClassConstantPoolCompactor.BridgeUsage mixed =
                StringClassConstantPoolCompactor.scanBridgeUsage(
                        Collections.singletonList(root), bridge);
        assertTrue(mixed.byteCarrierCalled);
        assertTrue(mixed.stringCarrierCalled);
        Set<String> required = context.discoverRequiredDecryptorOriginalMethodKeys(
                Collections.singletonList(root));
        assertEquals(2, required.size());
        assertTrue(required.contains(bridge + "->decrypt([B[B)Ljava/lang/String;"));
        assertTrue(required.contains(bridge
                + "->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
    }

    @Test
    public void compactsSelectedDirectoryAndJarClassesWhilePreservingResources() throws Exception {
        StringEncryptionContext context = builtInContext();
        byte[] original = classWithUnusedConstant("fixture/library/Sample");
        Set<String> hashes = Collections.singleton(StringPlaintextVerifier.sha256(UNUSED_SECRET));

        File directory = temporary.newFolder("classes-dir");
        File classFile = new File(directory, "fixture/library/Sample.class");
        assertTrue(classFile.getParentFile().mkdirs());
        Files.write(classFile.toPath(), original);
        StringClassConstantPoolCompactor.VerificationResult before =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(directory), hashes);
        assertEquals(0, before.plaintextLeaks);
        assertEquals(0, before.runtimePlaintextLeaks);
        assertEquals(1, before.wholePoolPlaintextCollisions);
        assertEquals(1, StringClassConstantPoolCompactor.verifyNoPlaintext(
                Collections.singletonList(directory), hashes, true).plaintextLeaks);
        assertEquals(1, StringClassConstantPoolCompactor.compactOutputs(
                Collections.singletonList(directory), context));
        assertFalse(contains(Files.readAllBytes(classFile.toPath()), UNUSED_SECRET));
        StringClassConstantPoolCompactor.VerificationResult after =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(directory), hashes);
        assertEquals(0, after.plaintextLeaks);
        assertEquals(0, after.wholePoolPlaintextCollisions);

        File jar = new File(temporary.newFolder("classes-jar"), "classes.jar");
        byte[] resource = "resource-value".getBytes(StandardCharsets.UTF_8);
        byte[] resourceExtra = new byte[]{(byte) 0xfe, (byte) 0xca, 0, 0};
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar.toPath()))) {
            output.putNextEntry(new JarEntry("fixture/library/Sample.class"));
            output.write(original);
            output.closeEntry();
            JarEntry resourceEntry = new JarEntry("META-INF/example.txt");
            resourceEntry.setComment("preserved-comment");
            resourceEntry.setExtra(resourceExtra);
            output.putNextEntry(resourceEntry);
            output.write(resource);
            output.closeEntry();
        }
        assertEquals(1, StringClassConstantPoolCompactor.compactOutputs(
                Collections.singletonList(jar), context));
        try (JarFile compacted = new JarFile(jar)) {
            byte[] classBytes = compacted.getInputStream(
                    compacted.getJarEntry("fixture/library/Sample.class")).readAllBytes();
            byte[] resourceBytes = compacted.getInputStream(
                    compacted.getJarEntry("META-INF/example.txt")).readAllBytes();
            assertFalse(contains(classBytes, UNUSED_SECRET));
            assertArrayEquals(resource, resourceBytes);
            assertArrayEquals(resourceExtra,
                    compacted.getJarEntry("META-INF/example.txt").getExtra());
            assertEquals("preserved-comment",
                    compacted.getJarEntry("META-INF/example.txt").getComment());
        }

        File nestedJar = new File(directory, "jars/nested.jar");
        assertTrue(nestedJar.getParentFile().mkdirs());
        writeJar(nestedJar, original, false);
        assertEquals(1, StringClassConstantPoolCompactor.compactOutputs(
                Collections.singletonList(directory), context));
        try (JarFile compacted = new JarFile(nestedJar)) {
            assertFalse(contains(compacted.getInputStream(compacted.getJarEntry(
                    "fixture/library/Sample.class")).readAllBytes(), UNUSED_SECRET));
        }
    }

    @Test
    public void verifierScansExcludedClassesAcrossTheWholeArtifact() throws Exception {
        StringEncryptionContext context = builtInContext();
        File directory = temporary.newFolder("artifact-wide");
        File selected = new File(directory, "fixture/library/Sample.class");
        File excluded = new File(directory, "other/Excluded.class");
        assertTrue(selected.getParentFile().mkdirs());
        assertTrue(excluded.getParentFile().mkdirs());
        Files.write(selected.toPath(), classWithUnusedConstant("fixture/library/Sample"));
        Files.write(excluded.toPath(), classWithLdc("other/Excluded", UNUSED_SECRET));

        assertEquals(1, StringClassConstantPoolCompactor.compactOutputs(
                Collections.singletonList(directory), context));
        StringClassConstantPoolCompactor.VerificationResult result =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(directory), Collections.singleton(
                                StringPlaintextVerifier.sha256(UNUSED_SECRET)));

        assertEquals(2, result.classesScanned);
        assertEquals(1, result.plaintextLeaks);
        assertEquals(1, result.plaintextLeakOccurrences);
        assertEquals(1, result.runtimePlaintextLeaks);
        assertEquals(1, result.runtimePlaintextLeakOccurrences);
        assertEquals(2, result.ldcStringValuesScanned);
        assertTrue(result.wholePoolPlaintextCollisions >= 1);
    }

    @Test
    public void defaultGateIgnoresMetadataCollisionsButStrictModeRestoresWholePoolFailure()
            throws Exception {
        File root = temporary.newFolder("metadata-collisions");
        File direct = new File(root, "fixture/library/Direct.class");
        assertTrue(direct.getParentFile().mkdirs());
        Files.write(direct.toPath(), classWithMemberName("fixture/library/Direct", UNUSED_SECRET));
        File jar = new File(root, "nested/classes.jar");
        assertTrue(jar.getParentFile().mkdirs());
        writeJar(jar, classWithMemberName("fixture/library/JarEntry", UNUSED_SECRET), false);
        Set<String> hashes = Collections.singleton(StringPlaintextVerifier.sha256(UNUSED_SECRET));

        StringClassConstantPoolCompactor.VerificationResult normal =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), hashes);
        assertEquals(2, normal.classesScanned);
        assertEquals(0, normal.plaintextLeaks);
        assertEquals(0, normal.runtimePlaintextLeaks);
        assertEquals(1, normal.wholePoolPlaintextCollisions);
        assertEquals(2, normal.wholePoolPlaintextCollisionOccurrences);
        assertEquals(0, normal.ldcStringValuesScanned);
        assertFalse(normal.strictWholeStringPool);

        StringClassConstantPoolCompactor.VerificationResult strict =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), hashes, true);
        assertEquals(1, strict.plaintextLeaks);
        assertEquals(2, strict.plaintextLeakOccurrences);
        assertEquals(0, strict.runtimePlaintextLeaks);
        assertEquals(1, strict.wholePoolPlaintextCollisions);
        assertTrue(strict.strictWholeStringPool);
    }

    @Test
    public void scansLdcAndStaticConstantValueAsJvmRuntimePayloads() throws Exception {
        File root = temporary.newFolder("runtime-payloads");
        File classFile = new File(root, "fixture/library/Payloads.class");
        assertTrue(classFile.getParentFile().mkdirs());
        Files.write(classFile.toPath(), classWithLdcAndStaticConstant());
        Set<String> hashes = new java.util.HashSet<>();
        hashes.add(StringPlaintextVerifier.sha256(UNUSED_SECRET));
        hashes.add(StringPlaintextVerifier.sha256(LDC_SECRET));

        StringClassConstantPoolCompactor.VerificationResult result =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), hashes);
        assertEquals(2, result.plaintextLeaks);
        assertEquals(2, result.plaintextLeakOccurrences);
        assertEquals(2, result.runtimePlaintextLeaks);
        assertEquals(2, result.runtimePlaintextLeakOccurrences);
        assertEquals(1, result.ldcStringValuesScanned);
        assertEquals(1, result.staticStringValuesScanned);
        assertEquals(0, result.annotationStringValuesScanned);
        assertEquals(0, result.callSiteStringValuesScanned);
    }

    @Test
    public void recursivelyScansAnnotationStringValuesAcrossOwners() throws Exception {
        File root = temporary.newFolder("annotation-payloads");
        File classFile = new File(root, "fixture/library/Annotated.class");
        assertTrue(classFile.getParentFile().mkdirs());
        Files.write(classFile.toPath(), classWithAnnotationPayloads());
        Set<String> hashes = new java.util.HashSet<>();
        hashes.add(StringPlaintextVerifier.sha256(ANNOTATION_SECRET));
        hashes.add(StringPlaintextVerifier.sha256(NESTED_ANNOTATION_SECRET));

        StringClassConstantPoolCompactor.VerificationResult result =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), hashes);
        assertEquals(2, result.plaintextLeaks);
        assertEquals(4, result.plaintextLeakOccurrences);
        assertEquals(4, result.annotationStringValuesScanned);
        assertEquals(0, result.ldcStringValuesScanned);
        assertEquals(0, result.staticStringValuesScanned);
        assertEquals(0, result.callSiteStringValuesScanned);
    }

    @Test
    public void recursivelyScansInvokeDynamicAndConstantDynamicStringPayloads() throws Exception {
        File root = temporary.newFolder("bootstrap-payloads");
        File classFile = new File(root, "fixture/library/BootstrapPayloads.class");
        assertTrue(classFile.getParentFile().mkdirs());
        Files.write(classFile.toPath(), classWithBootstrapPayloads());
        Set<String> hashes = new java.util.HashSet<>();
        hashes.add(StringPlaintextVerifier.sha256(BOOTSTRAP_SECRET));
        hashes.add(StringPlaintextVerifier.sha256(CONSTANT_DYNAMIC_SECRET));
        hashes.add(StringPlaintextVerifier.sha256(INVOKE_DYNAMIC_NAME_SECRET));
        hashes.add(StringPlaintextVerifier.sha256(CONSTANT_DYNAMIC_NAME_SECRET));

        StringClassConstantPoolCompactor.VerificationResult result =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), hashes);
        assertEquals(4, result.plaintextLeaks);
        assertEquals(4, result.plaintextLeakOccurrences);
        assertEquals(4, result.callSiteStringValuesScanned);
        assertEquals(0, result.ldcStringValuesScanned);
    }

    @Test
    public void exactJavacConcatAndLambdaNamesRemainStructuralMetadata() throws Exception {
        File root = temporary.newFolder("compiler-call-sites");
        File lambda = new File(root, "CompiledLambdaFixture.class");
        try (InputStream input = CompiledLambdaFixture.class.getResourceAsStream(
                "CompiledLambdaFixture.class")) {
            assertTrue(input != null);
            Files.write(lambda.toPath(), input.readAllBytes());
        }
        File concat = new File(root, "Concat.class");
        Files.write(concat.toPath(), classWithJavacStringConcat());
        Set<String> names = new java.util.HashSet<>();
        names.add(StringPlaintextVerifier.sha256("run"));
        names.add(StringPlaintextVerifier.sha256("makeConcatWithConstants"));

        StringClassConstantPoolCompactor.VerificationResult normal =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), names);
        assertEquals(0, normal.plaintextLeaks);
        // The placeholder recipe remains a scanned call-site value; both structural names do not.
        assertEquals(1, normal.callSiteStringValuesScanned);
        assertEquals(2, normal.wholePoolPlaintextCollisions);

        StringClassConstantPoolCompactor.VerificationResult strict =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(root), names, true);
        assertEquals(2, strict.plaintextLeaks);
    }

    @Test
    public void exactJavacRecordComponentNamesAreMetadataButMalformedShapeIsPayload()
            throws Exception {
        File root = temporary.newFolder("record-metadata");
        File compiled = new File(root, "CompiledRecordFixture.class");
        try (InputStream input = CompiledRecordFixture.class.getResourceAsStream(
                "CompiledRecordFixture.class")) {
            assertTrue(input != null);
            Files.write(compiled.toPath(), input.readAllBytes());
        }
        String componentNames = "label;count";
        Set<String> componentHash = new java.util.HashSet<>();
        componentHash.add(StringPlaintextVerifier.sha256(componentNames));
        componentHash.add(StringPlaintextVerifier.sha256("toString"));

        StringClassConstantPoolCompactor.VerificationResult normal =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(compiled), componentHash);
        assertEquals(0, normal.plaintextLeaks);
        assertEquals(0, normal.callSiteStringValuesScanned);
        assertEquals(2, normal.wholePoolPlaintextCollisions);
        assertEquals(2, StringClassConstantPoolCompactor.verifyNoPlaintext(
                Collections.singletonList(compiled), componentHash, true).plaintextLeaks);

        File forged = new File(root, "ForgedRecord.class");
        Files.write(forged.toPath(), forgedRecordWithBootstrapString(BOOTSTRAP_SECRET));
        StringClassConstantPoolCompactor.VerificationResult malformed =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(forged), Collections.singleton(
                                StringPlaintextVerifier.sha256(BOOTSTRAP_SECRET)));
        assertEquals(1, malformed.plaintextLeaks);
        assertEquals(2, malformed.callSiteStringValuesScanned);
    }

    @Test
    public void verifierReadsSignedJarWithoutRewritingIt() throws Exception {
        File jar = new File(temporary.newFolder("signed-verification"), "signed.jar");
        writeJar(jar, classWithLdc("fixture/library/Sample", LDC_SECRET), true);
        byte[] before = Files.readAllBytes(jar.toPath());

        StringClassConstantPoolCompactor.VerificationResult result =
                StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(jar), Collections.singleton(
                                StringPlaintextVerifier.sha256(LDC_SECRET)));
        assertEquals(1, result.plaintextLeaks);
        assertEquals(1, result.classesScanned);
        assertArrayEquals(before, Files.readAllBytes(jar.toPath()));
    }

    @Test
    public void refusesUnknownAttributesAndSignedJarRewrite() throws Exception {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "fixture/library/Attributed",
                null, "java/lang/Object", null);
        writer.visitAttribute(new Attribute("VendorConstantPoolIndexes") {
            @Override
            protected ByteVector write(ClassWriter classWriter, byte[] code, int codeLength,
                                       int maxStack, int maxLocals) {
                return new ByteVector().putByte(0);
            }
        });
        writer.visitEnd();
        IllegalArgumentException attributeFailure = assertThrows(IllegalArgumentException.class,
                () -> StringClassConstantPoolCompactor.compactClass(writer.toByteArray()));
        assertTrue(attributeFailure.getMessage().contains("unknown class attribute"));

        File attributed = new File(temporary.newFolder("attributed-verification"),
                "Attributed.class");
        Files.write(attributed.toPath(), writer.toByteArray());
        IOException verificationFailure = assertThrows(IOException.class,
                () -> StringClassConstantPoolCompactor.verifyNoPlaintext(
                        Collections.singletonList(attributed), Collections.emptySet()));
        assertTrue(verificationFailure.getMessage().contains("semantically verify JVM class"));
        assertTrue(verificationFailure.getCause().getMessage().contains("unknown class attribute"));

        StringEncryptionContext context = builtInContext();
        File jar = new File(temporary.newFolder("signed-jar"), "signed.jar");
        writeJar(jar, classWithUnusedConstant("fixture/library/Sample"), true);
        byte[] originalJar = Files.readAllBytes(jar.toPath());
        IOException signatureFailure = assertThrows(IOException.class,
                () -> StringClassConstantPoolCompactor.compactOutputs(
                        Collections.singletonList(jar), context));
        assertTrue(signatureFailure.getMessage().contains("signed class JAR"));
        assertArrayEquals(originalJar, Files.readAllBytes(jar.toPath()));
    }

    private static StringEncryptionContext builtInContext() {
        StringEncryptionContext context = StringEncryptionContext.create(null, null, null,
                Collections.singletonList("fixture.library"), Collections.emptyList(),
                "fixture.library.GeneratedBridge", StringEncryptionMode.BASE64,
                17L, 16_384, false, true, false, true);
        context.encrypt(UNUSED_SECRET, "fixture/library/Sample",
                "fixture/library/Sample->value()Ljava/lang/String;#0");
        return context;
    }

    private static void writeJar(File jar, byte[] classBytes, boolean signed) throws IOException {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar.toPath()))) {
            output.putNextEntry(new JarEntry("fixture/library/Sample.class"));
            output.write(classBytes);
            output.closeEntry();
            if (signed) {
                output.putNextEntry(new JarEntry("META-INF/TEST.SF"));
                output.write("signature".getBytes(StandardCharsets.UTF_8));
                output.closeEntry();
            }
        }
    }

    private static byte[] classWithUnusedConstant(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                internalName, null, "java/lang/Object", null);
        writer.newConst(UNUSED_SECRET);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn("carrier");
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithMemberName(String internalName, String memberName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                internalName, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                memberName, "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithLdc(String internalName, String value) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                internalName, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithBridgeCall(String internalName, String bridge,
                                              String descriptor) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                internalName, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        if ("([B[B)Ljava/lang/String;".equals(descriptor)) {
            method.visitInsn(Opcodes.ICONST_0);
            method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            method.visitInsn(Opcodes.ICONST_0);
            method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        } else {
            method.visitLdcInsn("ciphertext");
            method.visitLdcInsn("key");
        }
        method.visitMethodInsn(Opcodes.INVOKESTATIC, bridge, "decrypt", descriptor, false);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(2, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithLdcAndStaticConstant() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixture/library/Payloads", null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "STATIC_VALUE", "Ljava/lang/String;", null, UNUSED_SECRET).visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(LDC_SECRET);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithAnnotationPayloads() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixture/library/Annotated", null, "java/lang/Object", null);
        AnnotationVisitor classAnnotation = writer.visitAnnotation("Lfixture/Marker;", true);
        classAnnotation.visit("direct", ANNOTATION_SECRET);
        AnnotationVisitor nested = classAnnotation.visitAnnotation("nested",
                "Lfixture/Nested;");
        nested.visit("value", NESTED_ANNOTATION_SECRET);
        nested.visitEnd();
        classAnnotation.visitEnd();

        org.objectweb.asm.FieldVisitor field = writer.visitField(Opcodes.ACC_PUBLIC,
                "field", "Ljava/lang/String;", null, null);
        AnnotationVisitor fieldAnnotation = field.visitAnnotation("Lfixture/Marker;", false);
        fieldAnnotation.visit("value", ANNOTATION_SECRET);
        fieldAnnotation.visitEnd();
        field.visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()V", null, null);
        AnnotationVisitor methodAnnotation = method.visitAnnotation("Lfixture/Marker;", true);
        AnnotationVisitor array = methodAnnotation.visitArray("values");
        array.visit(null, NESTED_ANNOTATION_SECRET);
        array.visitEnd();
        methodAnnotation.visitEnd();
        method.visitCode();
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithBootstrapPayloads() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixture/library/BootstrapPayloads", null, "java/lang/Object", null);
        Handle invokeBootstrap = new Handle(Opcodes.H_INVOKESTATIC,
                "fixture/library/Bootstrap", "invoke",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                        + "Ljava/lang/invoke/MethodType;Ljava/lang/String;)"
                        + "Ljava/lang/invoke/CallSite;", false);
        Handle constantBootstrap = new Handle(Opcodes.H_INVOKESTATIC,
                "fixture/library/Bootstrap", "constant",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                        + "Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;", false);
        ConstantDynamic dynamic = new ConstantDynamic(CONSTANT_DYNAMIC_NAME_SECRET,
                "Ljava/lang/String;",
                constantBootstrap, CONSTANT_DYNAMIC_SECRET);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()V", null, null);
        method.visitCode();
        method.visitInvokeDynamicInsn(INVOKE_DYNAMIC_NAME_SECRET,
                "()Ljava/lang/String;", invokeBootstrap,
                BOOTSTRAP_SECRET);
        method.visitInsn(Opcodes.POP);
        method.visitLdcInsn(dynamic);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] classWithJavacStringConcat() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixture/library/Concat", null, "java/lang/Object", null);
        Handle bootstrap = new Handle(Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/StringConcatFactory", "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                        + "Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)"
                        + "Ljava/lang/invoke/CallSite;", false);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "concat", "(Ljava/lang/Object;)Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInvokeDynamicInsn("makeConcatWithConstants",
                "(Ljava/lang/Object;)Ljava/lang/String;", bootstrap,
                Character.toString((char) 1));
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] forgedRecordWithBootstrapString(String bootstrapString) {
        String owner = "fixture/library/ForgedRecord";
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_RECORD,
                owner, null, "java/lang/Record", null);
        writer.visitRecordComponent("label", "Ljava/lang/String;", null).visitEnd();
        writer.visitRecordComponent("count", "I", null).visitEnd();
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "label",
                "Ljava/lang/String;", null, null).visitEnd();
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "count",
                "I", null, null).visitEnd();
        Handle objectMethods = new Handle(Opcodes.H_INVOKESTATIC,
                "java/lang/runtime/ObjectMethods", "bootstrap",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                        + "Ljava/lang/invoke/TypeDescriptor;Ljava/lang/Class;Ljava/lang/String;"
                        + "[Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;", false);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "toString", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInvokeDynamicInsn("toString", "(L" + owner + ";)Ljava/lang/String;",
                objectMethods, org.objectweb.asm.Type.getObjectType(owner), bootstrapString,
                new Handle(Opcodes.H_GETFIELD, owner, "label", "Ljava/lang/String;", false),
                new Handle(Opcodes.H_GETFIELD, owner, "count", "I", false));
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static boolean contains(byte[] haystack, String needle) {
        byte[] value = needle.getBytes(StandardCharsets.UTF_8);
        outer:
        for (int i = 0; i <= haystack.length - value.length; i++) {
            for (int j = 0; j < value.length; j++) {
                if (haystack[i + j] != value[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
