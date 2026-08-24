package com.hunter.dexcfgobf.string;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.AnnotationVisibility;
import com.android.tools.smali.dexlib2.MethodHandleType;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotation;
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotationElement;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableField;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableCallSiteReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodHandleReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodProtoReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableAnnotationEncodedValue;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableArrayEncodedValue;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableMethodHandleEncodedValue;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableMethodTypeEncodedValue;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class StringPlaintextVerifierTest {
    @Test
    public void findsTrackedPlaintextInFinalDexWithoutReturningItsValue() throws Exception {
        String secret = "final-dex-secret-中文-9217";
        MethodImplementationBuilder body = new MethodImplementationBuilder(1);
        body.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0,
                new ImmutableStringReference(secret)));
        body.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        ImmutableMethod method = new ImmutableMethod("Lfixture/Leak;", "value",
                Collections.emptyList(), "Ljava/lang/String;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), body.getMethodImplementation());
        ImmutableClassDef classDef = new ImmutableClassDef("Lfixture/Leak;",
                AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", Collections.emptyList(),
                null, Collections.emptySet(), Collections.emptyList(), Collections.emptyList(),
                Collections.singleton(method), Collections.emptySet());

        Path root = Files.createTempDirectory("dex-string-verify-");
        Path dex = root.resolve("nested/classes.dex");
        Files.createDirectories(dex.getParent());
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(classDef);
        pool.writeTo(new FileDataStore(dex.toFile()));
        try {
            StringPlaintextVerifier.Result result =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Arrays.asList(root.toFile(), dex.getParent().toFile()),
                            new HashSet<>(Arrays.asList(
                                    StringPlaintextVerifier.sha256(secret),
                                    StringPlaintextVerifier.sha256("not-present"))),
                            Collections.singletonMap("fixture/Leak",
                                    new HashSet<>(Arrays.asList(
                                            StringPlaintextVerifier.sha256(secret),
                                            StringPlaintextVerifier.sha256("not-present")))),
                            Collections.singletonMap(
                                    "fixture/Leak->value()Ljava/lang/String;",
                                    Collections.singleton(
                                            StringPlaintextVerifier.sha256(secret))),
                            Collections.emptyMap(),
                            false);
            assertEquals(1, result.dexFilesScanned);
            assertEquals(2, result.plaintextHashesTracked);
            assertEquals(1, result.plaintextLeaks);
            assertEquals(1, result.plaintextLeakOccurrences);
            assertEquals(1, result.runtimePlaintextLeaks);
            assertEquals(1, result.scopedRuntimePlaintextLeaks);
            assertEquals(1, result.ownerRuntimePlaintextCollisions);
            assertEquals(1, result.globalRuntimePlaintextCollisions);
            assertEquals(1, result.targetClassesResolved);
            assertEquals(1, result.targetClassesScanned);
            assertEquals(1, result.constStringReferencesScanned);
            assertEquals(0, result.staticStringValuesScanned);
            assertEquals(0, result.annotationStringValuesScanned);
            assertEquals(0, result.callSiteStringValuesScanned);
            assertEquals(1, result.wholePoolPlaintextCollisions);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(dex.getParent());
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void metadataNameCollisionIsDiagnosticOnlyUnlessStrictModeIsEnabled() throws Exception {
        String metadataOnly = "metadataOnlyField9217";
        ImmutableField field = new ImmutableField("Lfixture/Metadata;", metadataOnly, "I",
                AccessFlags.PUBLIC.getValue(), null, Collections.emptySet(),
                Collections.emptySet());
        ImmutableClassDef classDef = classWith("Lfixture/Metadata;",
                Collections.emptySet(), Collections.singleton(field), Collections.emptySet());

        Path root = Files.createTempDirectory("dex-string-metadata-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.getDefault(), classDef);
            Set<String> hashes = Collections.singleton(
                    StringPlaintextVerifier.sha256(metadataOnly));

            StringPlaintextVerifier.Result normal =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/Metadata", hashes),
                            Collections.singletonMap("fixture/Metadata->protectedSite()V", hashes),
                            Collections.emptyMap(), false);
            assertEquals(0, normal.plaintextLeaks);
            assertEquals(0, normal.runtimePlaintextLeaks);
            assertEquals(1, normal.wholePoolPlaintextCollisions);
            assertEquals(1, normal.wholePoolPlaintextCollisionOccurrences);
            assertEquals(0, normal.constStringReferencesScanned);

            StringPlaintextVerifier.Result strict =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/Metadata", hashes),
                            Collections.singletonMap("fixture/Metadata->protectedSite()V", hashes),
                            Collections.emptyMap(), true);
            assertEquals(1, strict.plaintextLeaks);
            assertEquals(1, strict.plaintextLeakOccurrences);
            assertEquals(0, strict.runtimePlaintextLeaks);
            assertEquals(1, strict.wholePoolPlaintextCollisions);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void scansStaticAnnotationAndCallSiteStringPayloadsByCategory() throws Exception {
        String staticPayload = "static-payload-9217";
        String annotationPayload = "annotation-payload-8319";
        String nestedAnnotationPayload = "nested-annotation-payload-5413";
        String callSitePayload = "call-site-payload-4721";

        ImmutableField field = new ImmutableField("Lfixture/Payloads;", "stored",
                "Ljava/lang/String;", AccessFlags.PUBLIC.getValue()
                        | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(),
                new ImmutableStringEncodedValue(staticPayload), Collections.emptySet(),
                Collections.emptySet());
        ImmutableAnnotation annotation = new ImmutableAnnotation(AnnotationVisibility.RUNTIME,
                "Lfixture/Marker;", Arrays.asList(
                        new ImmutableAnnotationElement("value",
                                new ImmutableStringEncodedValue(annotationPayload)),
                        new ImmutableAnnotationElement("nested",
                                new ImmutableArrayEncodedValue(Collections.singletonList(
                                        new ImmutableAnnotationEncodedValue("Lfixture/Nested;",
                                                Collections.singleton(
                                                        new ImmutableAnnotationElement("value",
                                                                new ImmutableStringEncodedValue(
                                                                        nestedAnnotationPayload)))))))));

        ImmutableMethodReference bootstrapMethod = new ImmutableMethodReference(
                "Lfixture/Bootstrap;", "link",
                Arrays.asList("Ljava/lang/invoke/MethodHandles$Lookup;", "Ljava/lang/String;",
                        "Ljava/lang/invoke/MethodType;"), "Ljava/lang/invoke/CallSite;");
        ImmutableCallSiteReference callSite = new ImmutableCallSiteReference("site",
                new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC,
                        bootstrapMethod), "target",
                new ImmutableMethodProtoReference(Collections.emptyList(), "V"),
                Collections.singletonList(new ImmutableStringEncodedValue(callSitePayload)));
        MethodImplementationBuilder body = new MethodImplementationBuilder(0);
        body.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_CUSTOM,
                0, 0, 0, 0, 0, 0, callSite));
        body.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ImmutableMethod method = new ImmutableMethod("Lfixture/Payloads;", "invoke",
                Collections.emptyList(), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), body.getMethodImplementation());
        ImmutableClassDef classDef = classWith("Lfixture/Payloads;",
                Collections.singleton(annotation), Collections.singleton(field),
                Collections.singleton(method));

        Path root = Files.createTempDirectory("dex-string-payloads-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.forDexVersion(39), classDef);
            Set<String> hashes = new HashSet<>(Arrays.asList(
                    StringPlaintextVerifier.sha256(staticPayload),
                    StringPlaintextVerifier.sha256(annotationPayload),
                    StringPlaintextVerifier.sha256(nestedAnnotationPayload),
                    StringPlaintextVerifier.sha256(callSitePayload)));
            StringPlaintextVerifier.Result result =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/Payloads", hashes),
                            Collections.emptyMap(), Collections.singletonMap(
                                    "fixture/Payloads->stored", Collections.singleton(
                                            StringPlaintextVerifier.sha256(staticPayload))), false);

            assertEquals(1, result.plaintextLeaks);
            assertEquals(1, result.plaintextLeakOccurrences);
            assertEquals(1, result.runtimePlaintextLeaks);
            assertEquals(4, result.ownerRuntimePlaintextCollisions);
            assertEquals(4, result.globalRuntimePlaintextCollisions);
            assertEquals(1, result.staticStringValuesScanned);
            assertEquals(2, result.annotationStringValuesScanned);
            assertEquals(2, result.callSiteStringValuesScanned);
            assertEquals(0, result.constStringReferencesScanned);
            assertEquals(4, result.wholePoolPlaintextCollisions);

            StringPlaintextVerifier.Result fallback =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.emptyMap(), Collections.emptyMap(),
                            Collections.emptyMap(), hashes, false);
            assertEquals(4, fallback.plaintextLeaks);
            assertEquals(4, fallback.runtimePlaintextLeaks);
            assertEquals(0, fallback.scopedRuntimePlaintextLeaks);
            assertEquals(4, fallback.globalRuntimeFallbackHashesTracked);
            assertEquals(4, fallback.globalRuntimeFallbackPlaintextLeaks);
            assertEquals(4, fallback.globalRuntimeFallbackPlaintextLeakOccurrences);
            assertEquals(0, fallback.targetMethodsResolved);
            assertEquals(0, fallback.targetFieldsResolved);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void scansGenericCallSiteNamesAndSkipsOnlyExactCompilerStructures()
            throws Exception {
        String owner = "Lfixture/CallSiteNames;";
        String genericName = "generic-call-site-name-secret-9217";
        String malformedLambdaName = "malformed-lambda-name-secret-8319";
        String concatName = "makeConcatWithConstants";
        String lambdaName = "run";

        ImmutableMethodReference genericBootstrap = new ImmutableMethodReference(
                "Lfixture/Bootstrap;", "link",
                Arrays.asList("Ljava/lang/invoke/MethodHandles$Lookup;", "Ljava/lang/String;",
                        "Ljava/lang/invoke/MethodType;"), "Ljava/lang/invoke/CallSite;");
        ImmutableMethodReference concatBootstrap = new ImmutableMethodReference(
                "Ljava/lang/invoke/StringConcatFactory;", "makeConcatWithConstants",
                Arrays.asList("Ljava/lang/invoke/MethodHandles$Lookup;", "Ljava/lang/String;",
                        "Ljava/lang/invoke/MethodType;", "Ljava/lang/String;",
                        "[Ljava/lang/Object;"), "Ljava/lang/invoke/CallSite;");
        ImmutableMethodReference lambdaBootstrap = new ImmutableMethodReference(
                "Ljava/lang/invoke/LambdaMetafactory;", "metafactory",
                Arrays.asList("Ljava/lang/invoke/MethodHandles$Lookup;", "Ljava/lang/String;",
                        "Ljava/lang/invoke/MethodType;", "Ljava/lang/invoke/MethodType;",
                        "Ljava/lang/invoke/MethodHandle;", "Ljava/lang/invoke/MethodType;"),
                "Ljava/lang/invoke/CallSite;");
        ImmutableMethodReference lambdaBody = new ImmutableMethodReference(
                owner, "lambdaBody", Collections.emptyList(), "V");

        ImmutableCallSiteReference generic = new ImmutableCallSiteReference("genericSite",
                new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC,
                        genericBootstrap), genericName,
                new ImmutableMethodProtoReference(Collections.emptyList(), "V"),
                Collections.emptyList());
        ImmutableCallSiteReference concat = new ImmutableCallSiteReference("concatSite",
                new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC,
                        concatBootstrap), concatName,
                new ImmutableMethodProtoReference(
                        Collections.singletonList("Ljava/lang/Object;"),
                        "Ljava/lang/String;"),
                Collections.singletonList(new ImmutableStringEncodedValue(
                        Character.toString((char) 1))));
        ImmutableMethodProtoReference voidMethodType = new ImmutableMethodProtoReference(
                Collections.emptyList(), "V");
        java.util.List<com.android.tools.smali.dexlib2.iface.value.EncodedValue> lambdaArguments =
                Arrays.asList(new ImmutableMethodTypeEncodedValue(voidMethodType),
                        new ImmutableMethodHandleEncodedValue(
                                new ImmutableMethodHandleReference(
                                        MethodHandleType.INVOKE_STATIC, lambdaBody)),
                        new ImmutableMethodTypeEncodedValue(voidMethodType));
        ImmutableCallSiteReference lambda = new ImmutableCallSiteReference("lambdaSite",
                new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC,
                        lambdaBootstrap), lambdaName,
                new ImmutableMethodProtoReference(Collections.emptyList(),
                        "Ljava/lang/Runnable;"), lambdaArguments);
        ImmutableCallSiteReference malformedLambda = new ImmutableCallSiteReference(
                "malformedLambdaSite",
                new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC,
                        lambdaBootstrap), malformedLambdaName,
                new ImmutableMethodProtoReference(Collections.emptyList(),
                        "Ljava/lang/Runnable;"), Collections.emptyList());

        ImmutableMethod genericMethod = invokeCustomMethod(owner, "generic", generic, 0);
        ImmutableMethod concatMethod = invokeCustomMethod(owner, "concat", concat, 1);
        ImmutableMethod lambdaMethod = invokeCustomMethod(owner, "lambda", lambda, 0);
        ImmutableMethod malformedMethod = invokeCustomMethod(owner, "malformed",
                malformedLambda, 0);
        MethodImplementationBuilder lambdaBodyImplementation = new MethodImplementationBuilder(0);
        lambdaBodyImplementation.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ImmutableMethod lambdaBodyMethod = new ImmutableMethod(owner, "lambdaBody",
                Collections.emptyList(), "V",
                AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(),
                lambdaBodyImplementation.getMethodImplementation());
        ImmutableClassDef classDef = classWith(owner, Collections.emptySet(),
                Collections.emptySet(), Arrays.asList(genericMethod, concatMethod, lambdaMethod,
                        malformedMethod, lambdaBodyMethod));

        Path root = Files.createTempDirectory("dex-call-site-names-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.forDexVersion(39), classDef);
            Set<String> hashes = new HashSet<>(Arrays.asList(
                    StringPlaintextVerifier.sha256(genericName),
                    StringPlaintextVerifier.sha256(malformedLambdaName),
                    StringPlaintextVerifier.sha256(concatName),
                    StringPlaintextVerifier.sha256(lambdaName)));
            StringPlaintextVerifier.Result result =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.emptyMap(), Collections.emptyMap(),
                            Collections.emptyMap(), hashes, false);

            assertEquals(2, result.plaintextLeaks);
            assertEquals(2, result.globalRuntimeFallbackPlaintextLeaks);
            assertEquals(2, result.globalRuntimeFallbackPlaintextLeakOccurrences);
            assertEquals(2, result.globalRuntimePlaintextCollisions);
            // Generic + malformed lambda names and the concat placeholder recipe are scanned.
            assertEquals(3, result.callSiteStringValuesScanned);
            assertEquals(4, result.wholePoolPlaintextCollisions);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void sameValueInAnotherClassIsGlobalDiagnosticButNotScopedLeak() throws Exception {
        String shared = "shared-value-owned-elsewhere-9217";
        ImmutableClassDef target = classWith("Lfixture/Target;", Collections.emptySet(),
                Collections.emptySet(), Collections.emptySet());
        ImmutableClassDef thirdParty = constStringClass("Lthirdparty/Dependency;", shared);
        Path root = Files.createTempDirectory("dex-string-owner-scope-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.getDefault(), target, thirdParty);
            Set<String> hashes = Collections.singleton(StringPlaintextVerifier.sha256(shared));
            java.util.Map<String, Set<String>> targets =
                    Collections.singletonMap("fixture/Target", hashes);

            StringPlaintextVerifier.Result normal =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes, targets,
                            Collections.singletonMap("fixture/Target->protectedSite()V", hashes),
                            Collections.emptyMap(), false);

            assertEquals(0, normal.plaintextLeaks);
            assertEquals(0, normal.scopedRuntimePlaintextLeaks);
            assertEquals(1, normal.globalRuntimePlaintextCollisions);
            assertEquals(1, normal.globalRuntimePlaintextCollisionOccurrences);
            assertEquals(1, normal.wholePoolPlaintextCollisions);
            assertEquals(1, normal.targetClassesResolved);
            assertEquals(1, normal.targetClassesScanned);

            StringPlaintextVerifier.Result strict =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes, targets,
                            Collections.singletonMap("fixture/Target->protectedSite()V", hashes),
                            Collections.emptyMap(), true);
            assertEquals(1, strict.plaintextLeaks);
            assertEquals(0, strict.scopedRuntimePlaintextLeaks);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void sameValueInAnotherMethodOfTargetOwnerIsNotAScopedConstStringLeak()
            throws Exception {
        String shared = "same-owner-different-method-702431";
        String owner = "Lfixture/SameOwner;";
        ImmutableClassDef target = classWith(owner, Collections.emptySet(),
                Collections.emptySet(), Arrays.asList(
                        constStringMethod(owner, "protectedSite", "ciphertext-placeholder"),
                        constStringMethod(owner, "unrelated", shared)));
        Path root = Files.createTempDirectory("dex-string-method-scope-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.getDefault(), target);
            Set<String> hashes = Collections.singleton(StringPlaintextVerifier.sha256(shared));
            StringPlaintextVerifier.Result result =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/SameOwner", hashes),
                            Collections.singletonMap(
                                    "fixture/SameOwner->protectedSite()Ljava/lang/String;", hashes),
                            Collections.emptyMap(), false);

            assertEquals(0, result.plaintextLeaks);
            assertEquals(0, result.scopedRuntimePlaintextLeaks);
            assertEquals(1, result.ownerRuntimePlaintextCollisions);
            assertEquals(1, result.globalRuntimePlaintextCollisions);
            assertEquals(1, result.targetMethodsResolved);
            assertEquals(1, result.targetMethodsScanned);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void annotationKindsRemainPreciselyDiagnosedButAreNotExecutableSiteLeaks()
            throws Exception {
        String signature = "Lfixture/Generic<Ljava/lang/String;>;";
        String componentName = "componentName9217";
        String annotationDefault = "annotation-default-business-value-8319";
        String nestedUserValue = "record-user-annotation-value-5413";

        ImmutableAnnotation signatureAnnotation = new ImmutableAnnotation(
                AnnotationVisibility.SYSTEM, "Ldalvik/annotation/Signature;",
                Collections.singleton(new ImmutableAnnotationElement("value",
                        new ImmutableArrayEncodedValue(Collections.singletonList(
                                new ImmutableStringEncodedValue(signature))))));
        ImmutableAnnotation defaultAnnotation = new ImmutableAnnotation(
                AnnotationVisibility.SYSTEM, "Ldalvik/annotation/AnnotationDefault;",
                Collections.singleton(new ImmutableAnnotationElement("value",
                        new ImmutableStringEncodedValue(annotationDefault))));
        ImmutableAnnotationEncodedValue nestedUserAnnotation =
                new ImmutableAnnotationEncodedValue("Lfixture/UserMarker;",
                        Collections.singleton(new ImmutableAnnotationElement("value",
                                new ImmutableStringEncodedValue(nestedUserValue))));
        ImmutableAnnotation recordAnnotation = new ImmutableAnnotation(
                AnnotationVisibility.SYSTEM, "Ldalvik/annotation/Record;", Arrays.asList(
                        new ImmutableAnnotationElement("componentNames",
                                new ImmutableArrayEncodedValue(Collections.singletonList(
                                        new ImmutableStringEncodedValue(componentName)))),
                        new ImmutableAnnotationElement("componentAnnotations",
                                new ImmutableArrayEncodedValue(Collections.singletonList(
                                        new ImmutableArrayEncodedValue(Collections.singletonList(
                                                nestedUserAnnotation)))))));
        ImmutableClassDef target = classWith("Lfixture/AnnotatedTarget;",
                new HashSet<>(Arrays.asList(signatureAnnotation, defaultAnnotation,
                        recordAnnotation)), Collections.emptySet(), Collections.emptySet());

        Path root = Files.createTempDirectory("dex-string-structural-annotation-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.getDefault(), target);
            Set<String> hashes = new HashSet<>(Arrays.asList(
                    StringPlaintextVerifier.sha256(signature),
                    StringPlaintextVerifier.sha256(componentName),
                    StringPlaintextVerifier.sha256(annotationDefault),
                    StringPlaintextVerifier.sha256(nestedUserValue)));
            StringPlaintextVerifier.Result result =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/AnnotatedTarget", hashes),
                            Collections.singletonMap(
                                    "fixture/AnnotatedTarget->protectedSite()V", hashes),
                            Collections.emptyMap(), false);

            assertEquals(0, result.plaintextLeaks);
            assertEquals(0, result.scopedRuntimePlaintextLeaks);
            assertEquals(4, result.ownerRuntimePlaintextCollisions);
            assertEquals(4, result.globalRuntimePlaintextCollisions);
            assertEquals(4, result.annotationStringValuesScanned);
            assertEquals(2, result.structuralAnnotationStringValuesScanned);
            assertEquals(2, result.structuralAnnotationPlaintextCollisions);
            assertEquals(2, result.structuralAnnotationPlaintextCollisionOccurrences);

            StringPlaintextVerifier.Result fallback =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.emptyMap(), Collections.emptyMap(),
                            Collections.emptyMap(), hashes, false);
            assertEquals(2, fallback.plaintextLeaks);
            assertEquals(4, fallback.globalRuntimeFallbackHashesTracked);
            assertEquals(2, fallback.globalRuntimeFallbackPlaintextLeaks);
            assertEquals(2, fallback.globalRuntimeFallbackPlaintextLeakOccurrences);
            assertEquals(2, fallback.structuralAnnotationPlaintextCollisions);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void missingTargetOwnerScopeFailsClosed() throws Exception {
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> StringPlaintextVerifier.verifyDexDirectories(Collections.emptyList(),
                        Collections.singleton(StringPlaintextVerifier.sha256("tracked")),
                        Collections.emptyMap(), Collections.emptyMap(),
                        Collections.emptyMap(), false));
        assertEquals(true, failure.getMessage().contains("scope is empty"));
    }

    @Test
    public void completelyEmptyProtectedScopeIsAValidVerifiedResult() throws Exception {
        StringPlaintextVerifier.Result result = StringPlaintextVerifier.verifyDexDirectories(
                Collections.emptyList(), Collections.emptySet(), Collections.emptyMap(),
                Collections.emptyMap(), Collections.emptyMap(), Collections.emptySet(),
                Collections.emptySet(), Collections.emptySet(), false);

        assertEquals(0, result.plaintextHashesTracked);
        assertEquals(0, result.plaintextLeaks);
        assertEquals(0, result.targetClassesResolved);
        assertEquals(0, result.targetMethodsResolved);
    }

    @Test
    public void identityFieldProvenanceRequiresExactFinalOwnerNameAndStringDescriptor()
            throws Exception {
        String owner = "Lfixture/Identity;";
        ImmutableField field = new ImmutableField(owner, "VALUE", "Ljava/lang/String;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), null,
                Collections.emptySet(), Collections.emptySet());
        ImmutableField instanceField = new ImmutableField(owner, "INSTANCE",
                "Ljava/lang/String;", AccessFlags.PUBLIC.getValue(), null,
                Collections.emptySet(), Collections.emptySet());
        MethodImplementationBuilder body = new MethodImplementationBuilder(0);
        body.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ImmutableMethod clinit = new ImmutableMethod(owner, "<clinit>",
                Collections.emptyList(), "V", AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), body.getMethodImplementation());
        ImmutableClassDef classDef = classWith(owner, Collections.emptySet(),
                Arrays.asList(field, instanceField), Collections.singleton(clinit));
        Path root = Files.createTempDirectory("dex-string-identity-field-");
        Path dex = root.resolve("classes.dex");
        String hash = StringPlaintextVerifier.sha256("identity-field-value");
        Set<String> hashes = Collections.singleton(hash);
        try {
            writeDex(dex, Opcodes.getDefault(), classDef);
            StringPlaintextVerifier.Result exact =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/Identity", hashes),
                            Collections.singletonMap("fixture/Identity-><clinit>()V", hashes),
                            Collections.emptyMap(), Collections.emptySet(),
                            Collections.emptySet(), Collections.singleton(
                                    "fixture/Identity->VALUE:Ljava/lang/String;"), false);
            assertEquals(1, exact.targetMethodsResolved);
            assertEquals(1, exact.targetMethodsScanned);
            assertEquals(1, exact.identityFieldProvenanceResolved);
            assertEquals(1, exact.identityFieldProvenanceScanned);
            assertEquals(0, exact.targetFieldsResolved);

            StringPlaintextVerifier.Result wrongDescriptor =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/Identity", hashes),
                            Collections.singletonMap("fixture/Identity-><clinit>()V", hashes),
                            Collections.emptyMap(), Collections.emptySet(),
                            Collections.emptySet(), Collections.singleton(
                                    "fixture/Identity->VALUE:Ljava/lang/Object;"), false);
            assertEquals(1, wrongDescriptor.identityFieldProvenanceResolved);
            assertEquals(0, wrongDescriptor.identityFieldProvenanceScanned);

            StringPlaintextVerifier.Result nonStatic =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/Identity", hashes),
                            Collections.singletonMap("fixture/Identity-><clinit>()V", hashes),
                            Collections.emptyMap(), Collections.emptySet(),
                            Collections.emptySet(), Collections.singleton(
                                    "fixture/Identity->INSTANCE:Ljava/lang/String;"), false);
            assertEquals(1, nonStatic.identityFieldProvenanceResolved);
            assertEquals(0, nonStatic.identityFieldProvenanceScanned);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void affirmativelyRemovedSitesNeedNoRuntimeTargetOrFallback() throws Exception {
        String hash = StringPlaintextVerifier.sha256("removed-only");
        StringPlaintextVerifier.Result result = StringPlaintextVerifier.verifyDexDirectories(
                Collections.emptyList(), Collections.singleton(hash),
                Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap(),
                Collections.emptySet(), Collections.singleton(hash), Collections.emptySet(),
                false);
        assertEquals(1, result.removedOriginalSiteHashesTracked);
        assertEquals(0, result.targetMethodsResolved);
        assertEquals(0, result.globalRuntimeFallbackHashesTracked);
        assertEquals(0, result.plaintextLeaks);
    }

    @Test
    public void removedHashDoesNotSuppressTheSameHashAtMappedOrFallbackRuntimeSites()
            throws Exception {
        String exactValue = "removed-plus-exact";
        String fallbackValue = "removed-plus-fallback";
        String exactHash = StringPlaintextVerifier.sha256(exactValue);
        String fallbackHash = StringPlaintextVerifier.sha256(fallbackValue);
        Set<String> hashes = new HashSet<>(Arrays.asList(exactHash, fallbackHash));
        String owner = "Lfixture/RemovedOverlap;";
        ImmutableClassDef classDef = classWith(owner, Collections.emptySet(),
                Collections.emptySet(), Arrays.asList(
                        constStringMethod(owner, "exact", exactValue),
                        constStringMethod(owner, "fallback", fallbackValue)));
        Path root = Files.createTempDirectory("dex-string-removed-overlap-");
        Path dex = root.resolve("classes.dex");
        try {
            writeDex(dex, Opcodes.getDefault(), classDef);
            StringPlaintextVerifier.Result result =
                    StringPlaintextVerifier.verifyDexDirectories(
                            Collections.singleton(root.toFile()), hashes,
                            Collections.singletonMap("fixture/RemovedOverlap", hashes),
                            Collections.singletonMap(
                                    "fixture/RemovedOverlap->exact()Ljava/lang/String;",
                                    Collections.singleton(exactHash)),
                            Collections.emptyMap(), Collections.singleton(fallbackHash), hashes,
                            Collections.emptySet(), false);

            assertEquals(2, result.removedOriginalSiteHashesTracked);
            assertEquals(1, result.scopedRuntimePlaintextLeaks);
            assertEquals(1, result.globalRuntimeFallbackPlaintextLeaks);
            assertEquals(2, result.plaintextLeaks);
        } finally {
            Files.deleteIfExists(dex);
            Files.deleteIfExists(root);
        }
    }

    @Test
    public void iterableVerifierCountsUniqueLeaksAndOccurrences() {
        String hash = StringPlaintextVerifier.sha256("same");
        StringPlaintextVerifier.Result result = StringPlaintextVerifier.verifyStrings(
                Arrays.asList("same", "other", "same"), Collections.singleton(hash));
        assertEquals(3, result.stringPoolEntriesScanned);
        assertEquals(1, result.plaintextLeaks);
        assertEquals(2, result.plaintextLeakOccurrences);
    }

    private static ImmutableClassDef classWith(String type,
                                                Set<ImmutableAnnotation> annotations,
                                                Iterable<ImmutableField> fields,
                                                Iterable<ImmutableMethod> methods) {
        return new ImmutableClassDef(type, AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", Collections.emptyList(), null, annotations,
                fields, methods);
    }

    private static ImmutableClassDef constStringClass(String type, String value) {
        return classWith(type, Collections.emptySet(), Collections.emptySet(),
                Collections.singleton(constStringMethod(type, "value", value)));
    }

    private static ImmutableMethod constStringMethod(String type, String name, String value) {
        MethodImplementationBuilder body = new MethodImplementationBuilder(1);
        body.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0,
                new ImmutableStringReference(value)));
        body.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        return new ImmutableMethod(type, name, Collections.emptyList(),
                "Ljava/lang/String;", AccessFlags.PUBLIC.getValue()
                        | AccessFlags.STATIC.getValue(), Collections.emptySet(),
                Collections.emptySet(), body.getMethodImplementation());
    }

    private static ImmutableMethod invokeCustomMethod(
            String owner, String name, ImmutableCallSiteReference callSite,
            int argumentRegisters) {
        MethodImplementationBuilder body = new MethodImplementationBuilder(argumentRegisters);
        body.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_CUSTOM,
                argumentRegisters, 0, 0, 0, 0, 0, callSite));
        body.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        java.util.List<ImmutableMethodParameter> parameters = argumentRegisters == 0
                ? Collections.emptyList()
                : Collections.singletonList(new ImmutableMethodParameter(
                        "Ljava/lang/Object;", Collections.emptySet(), null));
        return new ImmutableMethod(owner, name, parameters, "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), body.getMethodImplementation());
    }

    private static void writeDex(Path dex, Opcodes opcodes, ClassDef... classes)
            throws Exception {
        DexPool pool = new DexPool(opcodes);
        for (ClassDef classDef : classes) pool.internClass(classDef);
        pool.writeTo(new FileDataStore(dex.toFile()));
    }
}
