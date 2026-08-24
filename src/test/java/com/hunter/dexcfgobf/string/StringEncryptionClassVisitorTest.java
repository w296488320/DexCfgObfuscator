package com.hunter.dexcfgobf.string;

import org.junit.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.CodeSizeEvaluator;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.AnnotationNode;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class StringEncryptionClassVisitorTest {
    private static final String FIXTURE_BINARY = "fixture.EncryptedFixture";
    private static final String FIXTURE_INTERNAL = "fixture/EncryptedFixture";
    private static final String STRING_DESCRIPTOR = "Ljava/lang/String;";
    private static final String BRIDGE_BINARY = RuntimeBridge.class.getName();
    private static final String BRIDGE_INTERNAL = BRIDGE_BINARY.replace('.', '/');
    private static final String CONCAT_DYNAMIC_ARGUMENT = Character.toString((char) 1);
    private static final String CONCAT_STATIC_ARGUMENT = Character.toString((char) 2);
    private static final Handle STRING_CONCAT_BOOTSTRAP = new Handle(Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory", "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)"
                    + "Ljava/lang/invoke/CallSite;", false);
    private static final Handle CONSTANT_DYNAMIC_BOOTSTRAP = new Handle(Opcodes.H_INVOKESTATIC,
            "fixture/Bootstrap", "constant",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;"
                    + "Ljava/lang/String;)Ljava/lang/Object;", false);
    private static final Handle GENERIC_BOOTSTRAP = new Handle(Opcodes.H_INVOKESTATIC,
            "fixture/Bootstrap", "callSite",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)"
                    + "Ljava/lang/invoke/CallSite;", false);
    private static final Handle LAMBDA_METAFACTORY_BOOTSTRAP = new Handle(
            Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory", "metafactory",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
                    + "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                    + "Ljava/lang/invoke/CallSite;", false);
    private static final Handle OBJECT_METHODS_BOOTSTRAP = new Handle(Opcodes.H_INVOKESTATIC,
            "java/lang/runtime/ObjectMethods", "bootstrap",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/TypeDescriptor;Ljava/lang/Class;Ljava/lang/String;"
                    + "[Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;", false);

    @Test
    public void bytesModeRemovesLiteralsPreservesStaticFinalAndIdentity() throws Exception {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        byte[] transformed = transform(fixture(false), context);
        ClassNode node = readNode(transformed);

        FieldNode secret = field(node, "SECRET");
        assertNotNull(secret);
        assertNull("ConstantValue must not leak the original literal", secret.value);
        assertFalse(hasLiteral(node, "field-secret"));
        assertFalse(hasLiteral(node, "method-secret-中文"));
        assertTrue(hasLiteral(node, "   "));
        assertTrue(hasDecryptCall(node, "([B[B)Ljava/lang/String;"));
        assertNotNull(method(node, "<clinit>"));

        Class<?> type = new FixtureLoader().define(FIXTURE_BINARY, transformed);
        Field runtimeField = type.getField("SECRET");
        Method direct = type.getMethod("direct");
        Method sameLiteral = type.getMethod("sameLiteral");
        assertEquals("field-secret", runtimeField.get(null));
        assertEquals("method-secret-中文", direct.invoke(null));
        assertSame("LDC string identity must remain interned", direct.invoke(null), sameLiteral.invoke(null));

        StringEncryptionSnapshot snapshot = context.snapshot();
        assertEquals(3, snapshot.constantsEncrypted);
        assertEquals(1, snapshot.classesModified);
        assertEquals(0, snapshot.identityCiphertexts);
        assertEquals(Collections.singleton(FIXTURE_BINARY),
                snapshot.modifiedOriginalClassNames);
        assertEquals(snapshot.encryptedPlaintextHashes,
                snapshot.encryptedPlaintextHashesByOriginalClass.get(FIXTURE_BINARY));
        assertEquals(3, snapshot.encryptedPlaintextHashesByOriginalMethod.size());
        assertEquals(1, snapshot.encryptedPlaintextHashesByOriginalField.size());
        String fieldHash = StringPlaintextVerifier.sha256("field-secret");
        assertEquals(Collections.singleton(fieldHash),
                snapshot.encryptedPlaintextHashesByOriginalMethod.get(
                        FIXTURE_INTERNAL + "-><clinit>()V"));
        assertEquals(Collections.singleton(fieldHash),
                snapshot.encryptedPlaintextHashesByOriginalField.get(
                        FIXTURE_INTERNAL + "->SECRET"));
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.modifiedOriginalClassNames.clear());
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.encryptedPlaintextHashesByOriginalClass.clear());
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.encryptedPlaintextHashesByOriginalClass
                        .get(FIXTURE_BINARY).clear());
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.encryptedPlaintextHashesByOriginalMethod.clear());
    }

    @Test
    public void base64ModeExecutesAndUsesCompactStringOverload() throws Exception {
        StringEncryptionContext context = context(StringEncryptionMode.BASE64);
        byte[] transformed = transform(fixture(false), context);
        ClassNode node = readNode(transformed);
        assertFalse(hasLiteral(node, "method-secret-中文"));
        assertTrue(hasDecryptCall(node,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));

        Class<?> type = new FixtureLoader().define(FIXTURE_BINARY, transformed);
        assertEquals("method-secret-中文", type.getMethod("direct").invoke(null));
    }

    @Test
    public void classIgnoreAnnotationLeavesConstantsUntouched() {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        byte[] transformed = transform(fixture(true), context);
        ClassNode node = readNode(transformed);
        assertTrue(hasLiteral(node, "method-secret-中文"));
        assertFalse(hasDecryptCall(node, "([B[B)Ljava/lang/String;"));
        assertEquals("field-secret", field(node, "SECRET").value);
    }

    @Test
    public void methodIgnoreAnnotationStillBypassesBufferedRewrite() {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        ClassNode node = readNode(transform(methodIgnoreFixture(), context));

        assertTrue(hasLiteral(node, "ignored-method-secret"));
        assertFalse(hasLiteral(node, "protected-method-secret"));
        assertTrue(hasDecryptCall(node, "([B[B)Ljava/lang/String;"));
        assertFalse(hasMethodMarker(method(node, "ignored"), context));
        assertTrue(hasMethodMarker(method(node, "protectedValue"), context));
    }

    @Test
    public void marksOnlyRenderedOrdinaryMethodsAndConstructorsNotClassInitializers() {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        ClassNode node = readNode(transform(fixture(false), context));

        assertEquals(BRIDGE_BINARY + "$ExactStringSite",
                context.getMethodMarkerAnnotationClassName());
        assertEquals("L" + BRIDGE_INTERNAL + "$ExactStringSite;",
                context.getMethodMarkerAnnotationDescriptor());
        assertTrue(hasMethodMarker(method(node, "direct"), context));
        assertTrue(hasMethodMarker(method(node, "sameLiteral"), context));
        assertFalse("skipped whitespace must not mark a method",
                hasMethodMarker(method(node, "blank"), context));
        assertFalse("field injection into <clinit> uses exact owner resolution instead",
                hasMethodMarker(method(node, "<clinit>"), context));

        ClassNode constructor = readNode(transform(
                constructorStringFixture("fixture/ConstructorFixture"), context));
        assertTrue(hasMethodMarker(method(constructor, "<init>"), context));
    }

    @Test
    public void filtersPackagesGeneratedClassesAndCustomRuntime() {
        String runtimeClass = RuntimeInstanceDecryptor.class.getName();
        StringEncryptionContext context = StringEncryptionContext.create(new LegacyCipher(), runtimeClass,
                null, Arrays.asList("fixture", getClass().getPackage().getName()),
                Collections.singletonList("fixture.excluded"), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false);
        assertTrue(context.shouldVisitClass("fixture.Feature"));
        assertTrue(context.shouldVisitClass("fixture.Feature$Inner"));
        assertFalse(context.shouldVisitClass("fixture.excluded.Feature"));
        assertFalse(context.shouldVisitClass(runtimeClass));
        assertFalse(context.shouldVisitClass(BRIDGE_BINARY));
        assertFalse(context.shouldVisitClass("fixture.R$string"));
        assertFalse(context.shouldVisitClass("other.Feature"));
    }

    @Test
    public void rejectsIdentityAndBrokenRoundTripByDefault() {
        StringEncryptionContext identity = StringEncryptionContext.create(new IdentityCipher(),
                IdentityCipher.class.getName(), null, Collections.singletonList("fixture"),
                Collections.emptyList(), BRIDGE_BINARY, StringEncryptionMode.BYTES,
                9L, 4096, false, true, false, false);
        IllegalArgumentException identityFailure = assertThrows(IllegalArgumentException.class,
                () -> identity.encrypt("secret", FIXTURE_INTERNAL, "identity"));
        assertTrue(identityFailure.getMessage().contains("string cipher returned plaintext bytes"));
        assertFalse(identityFailure.getMessage().contains("custom string cipher"));
        assertFalse(identityFailure.getMessage().contains("secret"));

        StringEncryptionContext broken = StringEncryptionContext.create(new BrokenCipher(),
                BrokenCipher.class.getName(), null, Collections.singletonList("fixture"),
                Collections.emptyList(), BRIDGE_BINARY, StringEncryptionMode.BYTES,
                9L, 4096, false, true, false, false);
        assertThrows(IllegalArgumentException.class,
                () -> broken.encrypt("secret", FIXTURE_INTERNAL, "broken"));
    }

    @Test
    public void supportsLegacyStringFogMethodNamesAndKeyGeneratorShape() {
        StringEncryptionContext context = StringEncryptionContext.create(new LegacyCipher(),
                LegacyCipher.class.getName(), new LegacyKeyGenerator(),
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false);
        EncryptedString encrypted = context.encrypt("legacy", FIXTURE_INTERNAL,
                FIXTURE_INTERNAL + "->legacy()V#0");
        assertNotNull(encrypted);
        assertEquals(4, encrypted.key.length);
        assertEquals(1, context.snapshot().constantsEncrypted);
    }

    @Test
    public void supportsStaticCipherWithoutPublicConstructor() {
        StringEncryptionContext context = StringEncryptionContext.create(null,
                StaticCipher.class.getName(), null, Collections.singletonList("fixture"),
                Collections.emptyList(), BRIDGE_BINARY, StringEncryptionMode.BYTES,
                1L, 4096, false, true, false, true);
        assertNotNull(context.encrypt("static-secret", FIXTURE_INTERNAL,
                FIXTURE_INTERNAL + "->staticSite()V#0"));

        assertThrows(IllegalArgumentException.class, () -> StringEncryptionContext.create(null,
                StaticCipher.class.getName(), null, Collections.singletonList("fixture"),
                Collections.emptyList(), BRIDGE_BINARY, StringEncryptionMode.BYTES,
                1L, 4096, false, true, false, false));
    }

    @Test
    public void validatesRuntimeDecryptContractIndependentlyFromBuildAlgorithm() {
        StringEncryptionContext instance = StringEncryptionContext.create(new LegacyCipher(),
                RuntimeInstanceDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false);
        assertNotNull(instance.encrypt("instance-runtime", FIXTURE_INTERNAL,
                FIXTURE_INTERNAL + "->instanceRuntime()V#0"));

        StringEncryptionContext statik = StringEncryptionContext.create(new LegacyCipher(),
                RuntimeStaticDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, true);
        assertNotNull(statik.encrypt("static-runtime", FIXTURE_INTERNAL,
                FIXTURE_INTERNAL + "->staticRuntime()V#0"));

        assertThrows(IllegalArgumentException.class, () -> StringEncryptionContext.create(
                new LegacyCipher(), LegacyCipher.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, true));
        assertThrows(IllegalArgumentException.class, () -> StringEncryptionContext.create(
                new LegacyCipher(), RuntimeStaticDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false));
        assertThrows(IllegalArgumentException.class, () -> StringEncryptionContext.create(
                new LegacyCipher(), PrivateConstructorRuntimeDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false));
        assertThrows(IllegalArgumentException.class, () -> StringEncryptionContext.create(
                new LegacyCipher(), WrongReturnRuntimeDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, true));
        assertThrows(IllegalArgumentException.class, () -> StringEncryptionContext.create(
                new LegacyCipher(), NonPublicRuntimeDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false));
    }

    @Test
    public void exposesOnlyActuallyUsedBridgeAndImplementationMethodsForRequiredCfg() {
        StringEncryptionContext builtIn = StringEncryptionContext.create(null, null, null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false);
        assertTrue(builtIn.getRequiredDecryptorOriginalMethodKeys().isEmpty());
        transform(fixture(false), builtIn);
        assertEquals(1, builtIn.getRequiredDecryptorOriginalMethodKeys().size());
        assertTrue(builtIn.getRequiredDecryptorOriginalMethodKeys().contains(
                BRIDGE_INTERNAL + "->decrypt([B[B)Ljava/lang/String;"));
        assertFalse(builtIn.getRequiredDecryptorOriginalMethodKeys().contains(
                BRIDGE_INTERNAL
                        + "->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));

        StringEncryptionContext inherited = StringEncryptionContext.create(new LegacyCipher(),
                InheritedRuntimeDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false);
        transform(fixture(false), inherited);
        assertEquals(2, inherited.getRequiredDecryptorOriginalMethodKeys().size());
        assertTrue(inherited.getRequiredDecryptorOriginalMethodKeys().contains(
                RuntimeDecryptorBase.class.getName().replace('.', '/')
                        + "->decrypt([B[B)Ljava/lang/String;"));
        assertFalse(inherited.getRequiredDecryptorOriginalMethodKeys().contains(
                InheritedRuntimeDecryptor.class.getName().replace('.', '/')
                        + "->decrypt([B[B)Ljava/lang/String;"));

        StringEncryptionContext base64 = StringEncryptionContext.create(null, null, null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BASE64, 1L, 4096, false, true, false, false);
        transform(fixture(false), base64);
        assertEquals(2, base64.getRequiredDecryptorOriginalMethodKeys().size());
        assertTrue(base64.getRequiredDecryptorOriginalMethodKeys().contains(
                BRIDGE_INTERNAL + "->decrypt([B[B)Ljava/lang/String;"));
        assertTrue(base64.getRequiredDecryptorOriginalMethodKeys().contains(
                BRIDGE_INTERNAL
                        + "->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
    }

    @Test
    public void rejectsBehaviorallyDifferentRuntimeDecryptorEvenWhenBuildRoundTripIsDisabled() {
        String secret = "runtime-contract-mismatch-secret";
        StringEncryptionContext context = StringEncryptionContext.create(new LegacyCipher(),
                WrongBehaviorRuntimeDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, false, false, false);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.encrypt(secret, FIXTURE_INTERNAL, "runtime-contract-site"));

        assertTrue(failure.getMessage().contains("runtime string implementation round-trip failed"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void rejectsImplementationWhoseConstructorStateDiffersAcrossRuntimeInstances() {
        String secret = "per-instance-state-mismatch-secret";
        StringEncryptionContext context = StringEncryptionContext.create(null,
                PerInstanceStateCipher.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.encrypt(secret, FIXTURE_INTERNAL, "independent-instance-site"));

        assertTrue(failure.getMessage().contains(
                "runtime string implementation round-trip failed"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void rejectsSeparateAlgorithmThatOnlyMatchesFirstRuntimeInstanceState() {
        PerInstanceStateCipher.resetForTest();
        String secret = "separate-algorithm-instance-state-mismatch-secret";
        StringEncryptionContext context = StringEncryptionContext.create(
                new FixedMaskCipher((byte) 1), PerInstanceStateCipher.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.encrypt(secret, FIXTURE_INTERNAL,
                        "separate-algorithm-independent-instance-site"));

        assertTrue(failure.getMessage().contains(
                "runtime string implementation round-trip failed"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void fingerprintsCustomObjectIdentityButKeepsBuiltInsDeterministic() {
        StringEncryptionContext firstCustom = StringEncryptionContext.create(
                new StatefulNoToStringCipher(1), RuntimeInstanceDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false);
        StringEncryptionContext secondCustom = StringEncryptionContext.create(
                new StatefulNoToStringCipher(2), RuntimeInstanceDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false);
        assertFalse(firstCustom.getConfigurationFingerprint().equals(
                secondCustom.getConfigurationFingerprint()));

        StringEncryptionContext firstBuiltIn = StringEncryptionContext.create(null, null, null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false);
        StringEncryptionContext secondBuiltIn = StringEncryptionContext.create(null, null, null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false);
        assertEquals(firstBuiltIn.getConfigurationFingerprint(),
                secondBuiltIn.getConfigurationFingerprint());
    }

    @Test
    public void reportsWhenBuildCannotInvokeRuntimeDecryptImplementation() {
        String secret = "runtime-invocation-failure-secret";
        StringEncryptionContext context = StringEncryptionContext.create(new LegacyCipher(),
                ThrowingStaticRuntimeDecryptor.class.getName(), null,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 1L, 4096, false, true, false, true);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.encrypt(secret, FIXTURE_INTERNAL, "runtime-invocation-site"));

        assertTrue(failure.getMessage().contains(
                "runtime string implementation decrypt failed at runtime-invocation-site"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void rejectsCheckedExceptionsInRuntimeDecryptAndInstanceConstructor() {
        IllegalArgumentException staticDecrypt = assertThrows(IllegalArgumentException.class,
                () -> StringEncryptionContext.create(new LegacyCipher(),
                        CheckedStaticRuntimeDecryptor.class.getName(), null,
                        Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                        StringEncryptionMode.BYTES, 1L, 4096, false, true, false, true));
        assertTrue(staticDecrypt.getMessage().contains("runtime decrypt must not declare checked exception"));

        IllegalArgumentException instanceDecrypt = assertThrows(IllegalArgumentException.class,
                () -> StringEncryptionContext.create(new LegacyCipher(),
                        CheckedInstanceRuntimeDecryptor.class.getName(), null,
                        Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                        StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false));
        assertTrue(instanceDecrypt.getMessage().contains("runtime decrypt must not declare checked exception"));

        IllegalArgumentException constructor = assertThrows(IllegalArgumentException.class,
                () -> StringEncryptionContext.create(new LegacyCipher(),
                        CheckedConstructorRuntimeDecryptor.class.getName(), null,
                        Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                        StringEncryptionMode.BYTES, 1L, 4096, false, true, false, false));
        assertTrue(constructor.getMessage().contains(
                "runtime implementation public no-arg constructor must not declare checked exception"));
    }

    @Test
    public void bytesModeChoosesOneCarrierForEachWholeMethod() throws Exception {
        String binaryName = "fixture.BudgetFixture";
        String internalName = binaryName.replace('.', '/');
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        byte[] transformed = transform(budgetFixture(internalName), context);
        ClassNode node = readNode(transformed);
        assertTrue(hasDecryptCall(node, "([B[B)Ljava/lang/String;"));
        assertTrue(hasDecryptCall(node,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertFalse(hasDecryptCall(method(node, "many"), "([B[B)Ljava/lang/String;"));
        assertTrue(hasDecryptCall(method(node, "many"),
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertTrue(hasDecryptCall(method(node, "small"), "([B[B)Ljava/lang/String;"));
        assertFalse(hasDecryptCall(method(node, "small"),
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));

        Class<?> type = new FixtureLoader().define(binaryName, transformed);
        assertEquals(longString('c'), type.getField("THREE").get(null));
        assertEquals(longString('c'), type.getMethod("many").invoke(null));
        assertEquals("small-method-secret", type.getMethod("small").invoke(null));
        assertEquals(7, context.snapshot().constantsEncrypted);
        assertEquals(4, context.snapshot().encryptedPlaintextHashes.size());
    }

    @Test
    public void largeMixedLengthMethodFallsBackAsAWholeWithoutLateFailure() throws Exception {
        String binaryName = "fixture.LargeMixedCarrierFixture";
        int stringCount = 224;
        String[] values = mixedLengthValues(stringCount);
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        byte[] transformed = transform(multiStringMethodFixture(
                binaryName.replace('.', '/'), 3_500, values), context);
        ClassNode node = readNode(transformed);
        MethodNode method = method(node, "many");

        assertFalse(hasDecryptCall(method, "([B[B)Ljava/lang/String;"));
        assertEquals(stringCount, countDecryptCalls(method,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertEquals(stringCount, context.snapshot().constantsEncrypted);
        assertEquals(stringCount, context.snapshot().encryptedPlaintextHashes.size());

        Class<?> type = new FixtureLoader().define(binaryName, transformed);
        assertEquals(values[stringCount - 1], type.getMethod("many").invoke(null));
    }

    @Test
    public void fallbackDryRunsDoNotRepeatCustomCipherOrKeyGeneratorCalls() {
        int stringCount = 224;
        CountingCipher cipher = new CountingCipher();
        CountingKeyGenerator keyGenerator = new CountingKeyGenerator();
        StringEncryptionContext context = StringEncryptionContext.create(cipher,
                CountingCipher.class.getName(), keyGenerator,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false, true);

        ClassNode node = readNode(transform(multiStringMethodFixture(
                "fixture/SingleInvocationFixture", 3_500, mixedLengthValues(stringCount)),
                context));

        assertFalse(hasDecryptCall(method(node, "many"), "([B[B)Ljava/lang/String;"));
        assertEquals(stringCount, cipher.shouldEncryptCalls);
        assertEquals(stringCount, cipher.encryptCalls);
        assertEquals(stringCount, cipher.decryptCalls);
        assertEquals(stringCount, keyGenerator.generateCalls);
        assertEquals(stringCount, context.snapshot().constantsEncrypted);
    }

    @Test
    public void existingClinitPlansInjectedFieldsAndBodyLiteralsTogether() throws Exception {
        String binaryName = "fixture.ExistingClinitCarrierFixture";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        byte[] transformed = transform(existingClinitFixture(
                binaryName.replace('.', '/')), context);
        ClassNode node = readNode(transformed);
        MethodNode clinit = method(node, "<clinit>");

        assertFalse(hasDecryptCall(clinit, "([B[B)Ljava/lang/String;"));
        assertEquals(4, countDecryptCalls(clinit,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        StringEncryptionSnapshot snapshot = context.snapshot();
        assertEquals(4, snapshot.constantsEncrypted);
        assertEquals(1, snapshot.encryptedPlaintextHashesByOriginalMethod.size());
        assertEquals(snapshot.encryptedPlaintextHashes,
                snapshot.encryptedPlaintextHashesByOriginalMethod.get(
                        binaryName.replace('.', '/') + "-><clinit>()V"));
        assertEquals(2, snapshot.encryptedPlaintextHashesByOriginalField.size());

        Class<?> type = new FixtureLoader().define(binaryName, transformed);
        assertEquals(longString('d'), type.getField("FIRST").get(null));
        assertEquals(longString('e'), type.getField("SECOND").get(null));
        assertEquals(longString('f'), type.getField("BODY").get(null));
    }

    @Test
    public void wholeMethodPlanningPreservesTryCatchAndRuntimeSemantics() throws Exception {
        String binaryName = "fixture.TryCatchCarrierFixture";
        int noiseCount = 180;
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        byte[] transformed = transform(tryCatchFixture(
                binaryName.replace('.', '/'), noiseCount), context);
        ClassNode node = readNode(transformed);
        MethodNode method = method(node, "guarded");

        assertEquals(1, method.tryCatchBlocks.size());
        assertFalse(hasDecryptCall(method, "([B[B)Ljava/lang/String;"));
        assertEquals(noiseCount + 2, countDecryptCalls(method,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertEquals(noiseCount + 2, context.snapshot().constantsEncrypted);

        Class<?> type = new FixtureLoader().define(binaryName, transformed);
        Method guarded = type.getMethod("guarded", boolean.class);
        assertEquals("try-success-secret", guarded.invoke(null, false));
        assertEquals("try-caught-secret", guarded.invoke(null, true));
    }

    @Test
    public void unchangedMethodBypassesConservativeMaxGateWhenNothingCanBeEncrypted() {
        String internalName = "fixture/UnchangedBranchHeavyFixture";
        byte[] original = branchHeavyNoCandidateFixture(internalName, 13_110);
        assertTrue(evaluatedMaxCodeSize(method(readNode(original), "unchanged")) > 65_535);

        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        ClassNode transformed = readNode(transform(original, context));

        assertNotNull(method(transformed, "unchanged"));
        assertFalse(hasDecryptCall(transformed, "([B[B)Ljava/lang/String;"));
        assertFalse(hasDecryptCall(transformed,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertEquals(0, context.snapshot().constantsEncrypted);
    }

    @Test
    public void nearLimitMethodFallsBackToBase64BeforeClassWriterLimit() {
        String binaryName = "fixture.NearLimitFallbackFixture";
        String secret = "near-limit-fallback-secret";
        byte[] transformed = transform(nearLimitMethodFixture(
                binaryName.replace('.', '/'), 65_400, secret),
                context(StringEncryptionMode.BYTES));

        ClassNode node = readNode(transformed);
        assertFalse(hasLiteral(node, secret));
        assertFalse(hasDecryptCall(node, "([B[B)Ljava/lang/String;"));
        assertTrue(hasDecryptCall(node,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
    }

    @Test
    public void methodWideBase64PlanAcceptsExactEvaluatedBoundAndReportsFirstByteOver() {
        String fitInternalName = "fixture/NearLimitExactFixture";
        ClassNode fit = readNode(transform(nearLimitMethodFixture(
                        fitInternalName, 65_525, "near-limit-exact-secret"),
                context(StringEncryptionMode.BYTES)));
        assertEquals(65_535, evaluatedMaxCodeSize(method(fit, "value")));

        String internalName = "fixture/NearLimitFailureFixture";
        String secret = "near-limit-failure-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(nearLimitMethodFixture(internalName, 65_526, secret), context));

        assertTrue(failure.getMessage().contains("JVM Code attribute limit"));
        assertTrue(failure.getMessage().contains(internalName + "->value()Ljava/lang/String;"));
        assertTrue(failure.getMessage().contains("BASE64 carrier"));
        assertTrue(failure.getMessage().contains("conservative max estimate"));
        assertTrue(failure.getMessage().contains("originalMaxCodeBytesEstimate=65530"));
        assertTrue(failure.getMessage().contains("plannedMaxCodeBytesEstimate=65536"));
        assertTrue(failure.getMessage().contains("requiredAdditionalBytesEstimate=6"));
        assertTrue(failure.getMessage().contains("excessBytesEstimate=1"));
        assertTrue(failure.getMessage().contains("encryptedConstants=1"));
        assertTrue(failure.getMessage().contains("carrier=BASE64"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().constantsEncrypted);
    }

    @Test
    public void nearLimitClassInitializerAccountsForPutStatic() {
        String internalName = "fixture/NearLimitClinitFixture";
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(nearLimitStaticFieldFixture(internalName, 65_524),
                        context(StringEncryptionMode.BYTES)));

        assertTrue(failure.getMessage().contains(internalName + "-><clinit>()V"));
        assertTrue(failure.getMessage().contains("method-wide BASE64 carrier"));
        assertTrue(failure.getMessage().contains("originalMaxCodeBytesEstimate=65525"));
        assertTrue(failure.getMessage().contains("plannedMaxCodeBytesEstimate=65537"));
        assertTrue(failure.getMessage().contains("requiredAdditionalBytesEstimate=12"));
        assertTrue(failure.getMessage().contains("encryptedConstants=1"));
    }

    @Test
    public void base64ModeRejectsOversizedCiphertextConstantBeforeAsmUtf8Failure() {
        String internalName = "fixture/Base64Utf8ValueFixture";
        String secret = repeatedString('v', 49_150);
        StringEncryptionContext context = context(StringEncryptionMode.BASE64, true,
                49_150, null);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(nearLimitMethodFixture(internalName, 0, secret), context));

        assertTrue(failure.getMessage().contains("BASE64 ciphertext"));
        assertTrue(failure.getMessage().contains("CONSTANT_Utf8 limit"));
        assertTrue(failure.getMessage().contains("encodedBytes=65536"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void base64ModeAllowsLargestWholeCarrierBelowUtf8Limit() {
        String internalName = "fixture/Base64Utf8BoundaryFixture";
        String secret = repeatedString('b', 49_149);
        StringEncryptionContext context = context(StringEncryptionMode.BASE64, true,
                49_149, null);

        ClassNode transformed = readNode(transform(
                nearLimitMethodFixture(internalName, 0, secret), context));

        assertFalse(hasLiteral(transformed, secret));
        assertTrue(hasDecryptCall(transformed,
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
    }

    @Test
    public void bytesFallbackRejectsOversizedKeyConstantBeforeAsmUtf8Failure() {
        String internalName = "fixture/Base64Utf8KeyFixture";
        String secret = "oversized-key-carrier-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES, true,
                49_150, new OversizedKeyGenerator());

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(nearLimitMethodFixture(internalName, 0, secret), context));

        assertTrue(failure.getMessage().contains("BASE64 key"));
        assertTrue(failure.getMessage().contains("CONSTANT_Utf8 limit"));
        assertTrue(failure.getMessage().contains("encodedBytes=65536"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void skipsUnpairedSurrogateButEncryptsEmojiAndNul() {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);
        assertNull(context.encrypt("broken-\uD800", FIXTURE_INTERNAL, "surrogate"));
        EncryptedString encrypted = context.encrypt("nul-\u0000-emoji-\uD83D\uDE00",
                FIXTURE_INTERNAL, FIXTURE_INTERNAL + "->unicode()V#0");
        assertNotNull(encrypted);
        assertEquals(1, context.snapshot().constantsEncrypted);
        assertEquals(1, context.snapshot().constantsSkipped);
        assertEquals(1, context.snapshot().skippedInvalidUnicode);
    }

    @Test
    public void classifiesEverySkippedStringReasonWithoutMixingUnsafeAndFiltered() {
        StringEncryptionContext context = StringEncryptionContext.create(new LegacyCipher(),
                LegacyCipher.class.getName(), null, Collections.singletonList("fixture"),
                Collections.emptyList(), BRIDGE_BINARY, StringEncryptionMode.BYTES,
                1L, 8, false, true, false, false);

        assertNull(context.encrypt("   ", FIXTURE_INTERNAL, "whitespace"));
        assertNull(context.encrypt("nine-bytes", FIXTURE_INTERNAL, "too-large"));
        assertNull(context.encrypt("broken-\uD800", FIXTURE_INTERNAL, "invalid-unicode"));
        assertNull(context.encrypt("skip-me", FIXTURE_INTERNAL, "custom-filter"));

        StringEncryptionSnapshot snapshot = context.snapshot();
        assertEquals(4, snapshot.constantsSkipped);
        assertEquals(1, snapshot.skippedWhitespace);
        assertEquals(1, snapshot.skippedTooLarge);
        assertEquals(1, snapshot.skippedInvalidUnicode);
        assertEquals(1, snapshot.skippedFiltered);
    }

    @Test
    public void rejectsStringConcatRecipeTextWithoutLeakingItInTheError() {
        String secret = "unsupported-concat-recipe-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(stringConcatFixture("fixture/ConcatRecipeFixture",
                        secret + "=" + CONCAT_DYNAMIC_ARGUMENT), context));

        assertTrue(failure.getMessage().contains("StringConcatFactory recipe"));
        assertTrue(failure.getMessage().contains("failOnUnsupportedStringConstants false"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void permissiveModeRetainsAndCountsStringConcatBootstrapText() {
        String secret = "retained-concat-bootstrap-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES, false);

        ClassNode node = readNode(transform(stringConcatFixture(
                "fixture/ConcatBootstrapFixture",
                CONCAT_STATIC_ARGUMENT + CONCAT_DYNAMIC_ARGUMENT, secret), context));

        assertTrue(hasInvokeDynamicBootstrapString(node, secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void placeholderOnlyStringConcatRecipeIsSupported() {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        transform(stringConcatFixture("fixture/PlaceholderConcatFixture",
                CONCAT_DYNAMIC_ARGUMENT), context);

        assertEquals(0, context.snapshot().unsupportedConstants);
    }

    @Test
    public void rejectsConstantDynamicBootstrapTextWithoutLeakingItInTheError() {
        String secret = "unsupported-condy-bootstrap-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(constantDynamicFixture("fixture/CondyFixture", secret), context));

        assertTrue(failure.getMessage().contains("ConstantDynamic bootstrap String"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void rejectsNonConcatInvokeDynamicBootstrapTextWithoutLeakingItInTheError() {
        String secret = "unsupported-generic-bootstrap-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(genericInvokeDynamicFixture(
                        "fixture/GenericBootstrapFixture", secret), context));

        assertTrue(failure.getMessage().contains("invokedynamic bootstrap String"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void rejectsGenericInvokeDynamicNameWithoutLeakingItInTheError() {
        String secret = "generic-invokedynamic-name-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(genericNamedInvokeDynamicFixture(
                        "fixture/GenericNameFixture", secret), context));

        assertTrue(failure.getMessage().contains("invokedynamic name"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void rejectsConstantDynamicNameWithoutLeakingItInTheError() {
        String secret = "generic-constant-dynamic-name-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(constantDynamicNameFixture(
                        "fixture/CondyNameFixture", secret), context));

        assertTrue(failure.getMessage().contains("ConstantDynamic name"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void acceptsExactJavacLambdaMetafactoryName() throws Exception {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        transform(classBytes(CompiledLambdaFixture.class), context);

        assertEquals(0, context.snapshot().unsupportedConstants);
    }

    @Test
    public void malformedLambdaMetafactoryShapeCannotHideInvokeDynamicName() {
        String secret = "forged-lambda-name-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(malformedLambdaFixture(
                        "fixture/ForgedLambdaFixture", secret), context));

        assertTrue(failure.getMessage().contains("invokedynamic name"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void acceptsOnlyJavacRecordComponentMetadata() throws Exception {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        byte[] transformed = transform(classBytes(CompiledRecordFixture.class), context);
        ClassNode node = readNode(transformed);

        assertTrue(hasInvokeDynamicBootstrapString(node, "label;count"));
        assertEquals(0, context.snapshot().unsupportedConstants);

        Class<?> type = new FixtureLoader().define(CompiledRecordFixture.class.getName(),
                transformed);
        java.lang.reflect.Constructor<?> constructor =
                type.getDeclaredConstructor(String.class, int.class);
        constructor.setAccessible(true);
        Object value = constructor.newInstance("visible", 7);
        Object equivalent = constructor.newInstance("visible", 7);
        assertEquals("CompiledRecordFixture[label=visible, count=7]", value.toString());
        assertEquals(value, equivalent);
        assertEquals(value.hashCode(), equivalent.hashCode());
    }

    @Test
    public void rejectsObjectMethodsComponentTextOutsideARecord() {
        String componentText = "component";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(objectMethodsFixture("fixture/NotARecordFixture", false,
                        componentText), context));

        assertTrue(failure.getMessage().contains("invokedynamic bootstrap String"));
        assertFalse(failure.getMessage().contains(componentText));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void rejectsAllObjectMethodsStringsWhenBootstrapShapeIsNotCompilerGenerated() {
        String extraText = "extra-object-methods-bootstrap-secret";
        StringEncryptionContext context = context(StringEncryptionMode.BYTES, false);

        ClassNode node = readNode(transform(objectMethodsFixture(
                "fixture/ForgedRecordFixture", true, "component", extraText), context));

        assertTrue(hasInvokeDynamicBootstrapString(node, "component"));
        assertTrue(hasInvokeDynamicBootstrapString(node, extraText));
        assertEquals(3, context.snapshot().unsupportedConstants);
    }

    @Test
    public void rejectsNestedConstantDynamicInNonConcatInvokeDynamicBootstrap() {
        String secret = "unsupported-nested-condy-bootstrap-secret";
        ConstantDynamic nested = new ConstantDynamic("nested", "Ljava/lang/String;",
                CONSTANT_DYNAMIC_BOOTSTRAP, secret);
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> transform(genericInvokeDynamicFixture(
                        "fixture/NestedCondyBootstrapFixture", nested), context));

        assertTrue(failure.getMessage().contains("ConstantDynamic bootstrap String"));
        assertFalse(failure.getMessage().contains(secret));
        assertEquals(1, context.snapshot().unsupportedConstants);
    }

    @Test
    public void ordinaryAnnotationStringIsNotClassifiedAsExecutableUnsupportedText() {
        StringEncryptionContext context = context(StringEncryptionMode.BYTES);

        transform(annotationStringFixture("fixture/AnnotationFixture",
                "annotation-metadata-is-intentionally-out-of-scope"), context);

        assertEquals(0, context.snapshot().unsupportedConstants);
    }

    private static StringEncryptionContext context(StringEncryptionMode mode) {
        return context(mode, true);
    }

    private static StringEncryptionContext context(StringEncryptionMode mode,
                                                   boolean failOnUnsupportedStringConstants) {
        return context(mode, failOnUnsupportedStringConstants, 4096, null);
    }

    private static StringEncryptionContext context(StringEncryptionMode mode,
                                                   boolean failOnUnsupportedStringConstants,
                                                   int maxStringBytes,
                                                   Object keyGenerator) {
        return StringEncryptionContext.create(null, null, keyGenerator,
                Collections.singletonList("fixture"), Collections.emptyList(), BRIDGE_BINARY,
                mode, 0x123456789ABCDEFL, maxStringBytes, false, true, false, false,
                failOnUnsupportedStringConstants);
    }

    private static byte[] transform(byte[] original, StringEncryptionContext context) {
        ClassReader reader = new ClassReader(original);
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        reader.accept(new StringEncryptionClassVisitor(context, writer), 0);
        return writer.toByteArray();
    }

    private static byte[] classBytes(Class<?> type) throws Exception {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream input = type.getResourceAsStream(resource)) {
            assertNotNull("missing compiled fixture " + resource, input);
            return input.readAllBytes();
        }
    }

    private static byte[] fixture(boolean ignored) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, FIXTURE_INTERNAL, null,
                "java/lang/Object", null);
        if (ignored) {
            AnnotationVisitor annotation = writer.visitAnnotation(
                    "Lfixture/StringEncryptionIgnore;", false);
            annotation.visitEnd();
        }
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "SECRET", "Ljava/lang/String;", null, "field-secret").visitEnd();

        MethodVisitor ctor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(1, 1);
        ctor.visitEnd();

        stringMethod(writer, "direct", "method-secret-中文");
        stringMethod(writer, "sameLiteral", "method-secret-中文");
        stringMethod(writer, "blank", "   ");
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] constructorStringFixture(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V",
                null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>",
                "()V", false);
        constructor.visitLdcInsn("constructor-secret");
        constructor.visitInsn(Opcodes.POP);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] budgetFixture(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "ONE", "Ljava/lang/String;", null, longString('a')).visitEnd();
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "TWO", "Ljava/lang/String;", null, longString('b')).visitEnd();
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "THREE", "Ljava/lang/String;", null, longString('c')).visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "many", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(longString('a'));
        method.visitInsn(Opcodes.POP);
        method.visitLdcInsn(longString('b'));
        method.visitInsn(Opcodes.POP);
        method.visitLdcInsn(longString('c'));
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        stringMethod(writer, "small", "small-method-secret");
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static String[] mixedLengthValues(int count) {
        String[] values = new String[count];
        for (int i = 0; i < count; i++) {
            int length = 24 + (i * 37 % 97);
            values[i] = i + ":" + repeatedString((char) ('a' + i % 26), length);
        }
        return values;
    }

    private static byte[] multiStringMethodFixture(String internalName, int nopCount,
                                                   String[] values) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "many", "()Ljava/lang/String;", null, null);
        method.visitCode();
        for (int i = 0; i < nopCount; i++) method.visitInsn(Opcodes.NOP);
        for (int i = 0; i < values.length; i++) {
            method.visitLdcInsn(values[i]);
            method.visitInsn(i == values.length - 1 ? Opcodes.ARETURN : Opcodes.POP);
        }
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] tryCatchFixture(String internalName, int noiseCount) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "guarded", "(Z)Ljava/lang/String;", null, null);
        Label start = new Label();
        Label normal = new Label();
        Label end = new Label();
        Label handler = new Label();
        method.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException");
        method.visitCode();
        method.visitLabel(start);
        method.visitVarInsn(Opcodes.ILOAD, 0);
        method.visitJumpInsn(Opcodes.IFEQ, normal);
        method.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "()V", false);
        method.visitInsn(Opcodes.ATHROW);
        method.visitLabel(normal);
        for (int i = 0; i < noiseCount; i++) {
            method.visitLdcInsn("noise-" + i + "-"
                    + repeatedString((char) ('a' + i % 26), 48 + i % 53));
            method.visitInsn(Opcodes.POP);
        }
        method.visitLdcInsn("try-success-secret");
        method.visitInsn(Opcodes.ARETURN);
        method.visitLabel(end);
        method.visitLabel(handler);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        method.visitLdcInsn("try-caught-secret");
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(2, 2);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] existingClinitFixture(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "FIRST", STRING_DESCRIPTOR, null, longString('d')).visitEnd();
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "SECOND", STRING_DESCRIPTOR, null, longString('e')).visitEnd();
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "BODY", STRING_DESCRIPTOR, null, null).visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V",
                null, null);
        method.visitCode();
        method.visitLdcInsn(longString('f'));
        method.visitFieldInsn(Opcodes.PUTSTATIC, internalName, "BODY", STRING_DESCRIPTOR);
        method.visitLdcInsn(longString('g'));
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchHeavyNoCandidateFixture(String internalName, int jumpCount) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "unchanged", "()V", null, null);
        method.visitCode();
        for (int i = 0; i < jumpCount; i++) {
            Label next = new Label();
            method.visitJumpInsn(Opcodes.GOTO, next);
            method.visitLabel(next);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] methodIgnoreFixture() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, FIXTURE_INTERNAL, null,
                "java/lang/Object", null);
        MethodVisitor ignored = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "ignored", "()Ljava/lang/String;", null, null);
        ignored.visitAnnotation("Lfixture/StringEncryptionIgnore;", false).visitEnd();
        ignored.visitCode();
        ignored.visitLdcInsn("ignored-method-secret");
        ignored.visitInsn(Opcodes.ARETURN);
        ignored.visitMaxs(1, 0);
        ignored.visitEnd();
        stringMethod(writer, "protectedValue", "protected-method-secret");
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static String longString(char value) {
        return repeatedString(value, 4000);
    }

    private static String repeatedString(char value, int length) {
        char[] chars = new char[length];
        Arrays.fill(chars, value);
        return new String(chars);
    }

    private static byte[] nearLimitMethodFixture(String internalName, int nopCount,
                                                  String secret) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        for (int i = 0; i < nopCount; i++) method.visitInsn(Opcodes.NOP);
        method.visitLdcInsn(secret);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] nearLimitStaticFieldFixture(String internalName, int nopCount) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "SECRET", "Ljava/lang/String;", null, "near-limit-static-secret").visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V",
                null, null);
        method.visitCode();
        for (int i = 0; i < nopCount; i++) method.visitInsn(Opcodes.NOP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] stringConcatFixture(String internalName, String recipe,
                                              Object... bootstrapConstants) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "concat", "(Ljava/lang/Object;)Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        Object[] arguments = new Object[bootstrapConstants.length + 1];
        arguments[0] = recipe;
        System.arraycopy(bootstrapConstants, 0, arguments, 1, bootstrapConstants.length);
        method.visitInvokeDynamicInsn("makeConcatWithConstants",
                "(Ljava/lang/Object;)Ljava/lang/String;", STRING_CONCAT_BOOTSTRAP, arguments);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] constantDynamicFixture(String internalName, String bootstrapText) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(new ConstantDynamic("value", "Ljava/lang/String;",
                CONSTANT_DYNAMIC_BOOTSTRAP, bootstrapText));
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] genericInvokeDynamicFixture(String internalName,
                                                      Object... bootstrapArguments) {
        return genericNamedInvokeDynamicFixture(internalName, "value", bootstrapArguments);
    }

    private static byte[] genericNamedInvokeDynamicFixture(String internalName,
                                                           String invokeDynamicName,
                                                           Object... bootstrapArguments) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitInvokeDynamicInsn(invokeDynamicName, "()Ljava/lang/String;", GENERIC_BOOTSTRAP,
                bootstrapArguments);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] constantDynamicNameFixture(String internalName, String dynamicName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        Handle bootstrap = new Handle(Opcodes.H_INVOKESTATIC, "fixture/Bootstrap", "constant",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)"
                        + "Ljava/lang/Object;", false);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(new ConstantDynamic(dynamicName, "Ljava/lang/String;", bootstrap));
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] malformedLambdaFixture(String internalName, String dynamicName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/Runnable;", null, null);
        method.visitCode();
        method.visitInvokeDynamicInsn(dynamicName, "()Ljava/lang/Runnable;",
                LAMBDA_METAFACTORY_BOOTSTRAP);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] objectMethodsFixture(String internalName, boolean record,
                                               String componentNames,
                                               Object... extraArguments) {
        ClassWriter writer = new ClassWriter(0);
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        if (record) access |= Opcodes.ACC_RECORD;
        writer.visit(Opcodes.V17, access, internalName, null,
                record ? "java/lang/Record" : "java/lang/Object", null);
        if (record) {
            writer.visitRecordComponent("component", STRING_DESCRIPTOR, null).visitEnd();
        }
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "component",
                STRING_DESCRIPTOR, null, null).visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "toString",
                "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        Object[] arguments = new Object[3 + extraArguments.length];
        arguments[0] = Type.getObjectType(internalName);
        arguments[1] = componentNames;
        arguments[2] = new Handle(Opcodes.H_GETFIELD, internalName, "component",
                STRING_DESCRIPTOR, false);
        System.arraycopy(extraArguments, 0, arguments, 3, extraArguments.length);
        method.visitInvokeDynamicInsn("toString", "(L" + internalName
                + ";)Ljava/lang/String;", OBJECT_METHODS_BOOTSTRAP, arguments);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] annotationStringFixture(String internalName, String annotationText) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        AnnotationVisitor annotation = writer.visitAnnotation("Lfixture/Metadata;", false);
        annotation.visit("value", annotationText);
        annotation.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void stringMethod(ClassWriter writer, String name, String value) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, "()Ljava/lang/String;", null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
    }

    private static ClassNode readNode(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static boolean hasLiteral(ClassNode node, String value) {
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof LdcInsnNode
                        && value.equals(((LdcInsnNode) instruction).cst)) return true;
            }
        }
        return false;
    }

    private static boolean hasDecryptCall(ClassNode node, String descriptor) {
        for (MethodNode method : node.methods) {
            if (hasDecryptCall(method, descriptor)) return true;
        }
        return false;
    }

    private static boolean hasDecryptCall(MethodNode method, String descriptor) {
        return countDecryptCalls(method, descriptor) > 0;
    }

    private static boolean hasMethodMarker(MethodNode method,
                                           StringEncryptionContext context) {
        if (method == null || method.invisibleAnnotations == null) return false;
        for (AnnotationNode annotation : method.invisibleAnnotations) {
            if (context.getMethodMarkerAnnotationDescriptor().equals(annotation.desc)) return true;
        }
        return false;
    }

    private static int countDecryptCalls(MethodNode method, String descriptor) {
        int count = 0;
        for (AbstractInsnNode instruction : method.instructions) {
            if (instruction instanceof MethodInsnNode) {
                MethodInsnNode invoke = (MethodInsnNode) instruction;
                if (BRIDGE_INTERNAL.equals(invoke.owner) && "decrypt".equals(invoke.name)
                        && descriptor.equals(invoke.desc)) count++;
            }
        }
        return count;
    }

    private static int evaluatedMaxCodeSize(MethodNode method) {
        CodeSizeEvaluator evaluator = new CodeSizeEvaluator(null);
        method.accept(evaluator);
        return evaluator.getMaxSize();
    }

    private static boolean hasInvokeDynamicBootstrapString(ClassNode node, String value) {
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof InvokeDynamicInsnNode) {
                    for (Object argument : ((InvokeDynamicInsnNode) instruction).bsmArgs) {
                        if (value.equals(argument)) return true;
                    }
                }
            }
        }
        return false;
    }

    private static FieldNode field(ClassNode node, String name) {
        for (FieldNode field : node.fields) if (name.equals(field.name)) return field;
        return null;
    }

    private static MethodNode method(ClassNode node, String name) {
        for (MethodNode method : node.methods) if (name.equals(method.name)) return method;
        return null;
    }

    public static final class RuntimeBridge {
        public static String decrypt(byte[] value, byte[] key) {
            return new StreamXorStringCipher().decrypt(value, key).intern();
        }

        public static String decrypt(String value, String key) {
            return decrypt(Base64.getDecoder().decode(value), Base64.getDecoder().decode(key));
        }
    }

    public static final class IdentityCipher implements StringCipher {
        @Override public byte[] encrypt(String value, byte[] key) {
            return value.getBytes(StandardCharsets.UTF_8);
        }
        @Override public String decrypt(byte[] value, byte[] key) {
            return new String(value, StandardCharsets.UTF_8);
        }
    }

    public static final class CountingCipher implements StringCipher {
        int shouldEncryptCalls;
        int encryptCalls;
        int decryptCalls;

        public CountingCipher() {}

        @Override public boolean shouldEncrypt(String value) {
            shouldEncryptCalls++;
            return true;
        }

        @Override public byte[] encrypt(String value, byte[] key) {
            encryptCalls++;
            return StreamXorStringCipher.apply(value.getBytes(StandardCharsets.UTF_8), key);
        }

        @Override public String decrypt(byte[] value, byte[] key) {
            decryptCalls++;
            return new String(StreamXorStringCipher.apply(value, key), StandardCharsets.UTF_8);
        }
    }

    public static final class CountingKeyGenerator implements StringKeyGenerator {
        int generateCalls;

        @Override public byte[] generate(String value, String location) {
            generateCalls++;
            return new byte[]{3, 1, 4, 1};
        }
    }

    public static final class BrokenCipher implements StringCipher {
        @Override public byte[] encrypt(String value, byte[] key) { return new byte[]{1, 2, 3}; }
        @Override public String decrypt(byte[] value, byte[] key) { return "wrong"; }
    }

    public static final class LegacyCipher {
        public byte[] encrypt(String value, byte[] key) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
            return bytes;
        }
        public String decrypt(byte[] value, byte[] key) {
            byte[] bytes = value.clone();
            for (int i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
            return new String(bytes, StandardCharsets.UTF_8);
        }
        public boolean shouldFog(String value) { return !value.startsWith("skip"); }
    }

    public static final class LegacyKeyGenerator {
        public byte[] generate(String value) { return new byte[]{3, 1, 4, 1}; }
    }

    public static final class StaticCipher {
        private StaticCipher() {}
        public static byte[] encrypt(String value, byte[] key) {
            return new LegacyCipher().encrypt(value, key);
        }
        public static String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class RuntimeInstanceDecryptor {
        public RuntimeInstanceDecryptor() {}
        public String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static class RuntimeDecryptorBase {
        public RuntimeDecryptorBase() {}
        public String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class InheritedRuntimeDecryptor extends RuntimeDecryptorBase {
        public InheritedRuntimeDecryptor() {}
    }

    public static final class PerInstanceStateCipher {
        private static final java.util.concurrent.atomic.AtomicInteger NEXT =
                new java.util.concurrent.atomic.AtomicInteger();
        private final byte instanceMask = (byte) NEXT.incrementAndGet();

        public PerInstanceStateCipher() {}

        static void resetForTest() {
            NEXT.set(0);
        }

        public byte[] encrypt(String value, byte[] key) {
            byte[] encrypted = new LegacyCipher().encrypt(value, key);
            for (int i = 0; i < encrypted.length; i++) encrypted[i] ^= instanceMask;
            return encrypted;
        }

        public String decrypt(byte[] value, byte[] key) {
            byte[] copy = value.clone();
            for (int i = 0; i < copy.length; i++) copy[i] ^= instanceMask;
            return new LegacyCipher().decrypt(copy, key);
        }
    }

    public static final class FixedMaskCipher implements StringCipher {
        private final byte mask;

        FixedMaskCipher(byte mask) {
            this.mask = mask;
        }

        @Override public byte[] encrypt(String value, byte[] key) {
            byte[] encrypted = new LegacyCipher().encrypt(value, key);
            for (int i = 0; i < encrypted.length; i++) encrypted[i] ^= mask;
            return encrypted;
        }

        @Override public String decrypt(byte[] value, byte[] key) {
            byte[] copy = value.clone();
            for (int i = 0; i < copy.length; i++) copy[i] ^= mask;
            return new LegacyCipher().decrypt(copy, key);
        }
    }

    public static final class StatefulNoToStringCipher implements StringCipher {
        private final int state;

        StatefulNoToStringCipher(int state) { this.state = state; }

        @Override public byte[] encrypt(String value, byte[] key) {
            return new LegacyCipher().encrypt(value + state, key);
        }

        @Override public String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class RuntimeStaticDecryptor {
        private RuntimeStaticDecryptor() {}
        public static String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class WrongBehaviorRuntimeDecryptor {
        public WrongBehaviorRuntimeDecryptor() {}
        public String decrypt(byte[] value, byte[] key) {
            return "wrong-runtime-value";
        }
    }

    public static final class CheckedStaticRuntimeDecryptor {
        private CheckedStaticRuntimeDecryptor() {}
        public static String decrypt(byte[] value, byte[] key) throws java.io.IOException {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class ThrowingStaticRuntimeDecryptor {
        private ThrowingStaticRuntimeDecryptor() {}
        public static String decrypt(byte[] value, byte[] key) {
            throw new IllegalStateException("runtime decrypt unavailable");
        }
    }

    public static final class CheckedInstanceRuntimeDecryptor {
        public CheckedInstanceRuntimeDecryptor() {}
        public String decrypt(byte[] value, byte[] key) throws java.io.IOException {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class CheckedConstructorRuntimeDecryptor {
        public CheckedConstructorRuntimeDecryptor() throws java.io.IOException {}
        public String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class OversizedKeyGenerator implements StringKeyGenerator {
        @Override
        public byte[] generate(String value, String location) {
            byte[] key = new byte[49_150];
            Arrays.fill(key, (byte) 7);
            return key;
        }
    }

    public static final class PrivateConstructorRuntimeDecryptor {
        private PrivateConstructorRuntimeDecryptor() {}
        public String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    public static final class WrongReturnRuntimeDecryptor {
        private WrongReturnRuntimeDecryptor() {}
        public static Object decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    static final class NonPublicRuntimeDecryptor {
        public NonPublicRuntimeDecryptor() {}
        public String decrypt(byte[] value, byte[] key) {
            return new LegacyCipher().decrypt(value, key);
        }
    }

    private static final class FixtureLoader extends ClassLoader {
        FixtureLoader() { super(StringEncryptionClassVisitorTest.class.getClassLoader()); }
        Class<?> define(String name, byte[] bytes) { return defineClass(name, bytes, 0, bytes.length); }
    }
}
