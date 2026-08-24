package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction45cc;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodProtoReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Arrays;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ReportAndStructuralVerifierTest {
    @Test
    public void aggregatesStringGateDiagnosticsWithoutLosingTheEffectiveMode() {
        ObfuscatorStats first = new ObfuscatorStats();
        first.stringPlaintextVerified = true;
        first.stringPlaintextGateMode = "RUNTIME_PAYLOAD";
        first.stringPlaintextLeaks = 1;
        first.stringPlaintextLeakOccurrences = 2;
        first.stringRuntimePlaintextLeaks = 1;
        first.stringRuntimePlaintextLeakOccurrences = 2;
        first.stringScopedRuntimePlaintextLeaks = 1;
        first.stringScopedRuntimePlaintextLeakOccurrences = 2;
        first.stringGlobalRuntimeFallbackHashesTracked = 3;
        first.stringGlobalRuntimeFallbackPlaintextLeaks = 1;
        first.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = 2;
        first.stringOwnerRuntimePlaintextCollisions = 2;
        first.stringOwnerRuntimePlaintextCollisionOccurrences = 3;
        first.stringGlobalRuntimePlaintextCollisions = 3;
        first.stringGlobalRuntimePlaintextCollisionOccurrences = 4;
        first.stringTargetClassesResolved = 5;
        first.stringTargetClassesScanned = 4;
        first.stringTargetMethodsResolved = 7;
        first.stringTargetMethodsScanned = 6;
        first.stringTargetFieldsResolved = 3;
        first.stringTargetFieldsScanned = 2;
        first.stringR8MappedMethodSites = 1;
        first.stringR8RemovedMethodSites = 2;
        first.stringR8IdentityMethodSites = 3;
        first.stringR8FallbackMethodSites = 4;
        first.stringR8MappedFieldProvenance = 5;
        first.stringR8RemovedFieldProvenance = 6;
        first.stringR8IdentityFieldProvenance = 7;
        first.stringR8FallbackFieldProvenance = 8;
        first.stringRemovedOriginalSiteHashesTracked = 9;
        first.stringIdentityFieldProvenanceResolved = 10;
        first.stringIdentityFieldProvenanceScanned = 9;
        first.stringWholePoolPlaintextCollisions = 3;
        first.stringWholePoolPlaintextCollisionOccurrences = 4;
        first.stringConstStringReferencesScanned = 5;
        first.stringStaticStringValuesScanned = 6;
        first.stringAnnotationStringValuesScanned = 7;
        first.stringCallSiteStringValuesScanned = 8;

        ObfuscatorStats second = new ObfuscatorStats();
        second.stringPlaintextVerified = true;
        second.stringPlaintextGateMode = "RUNTIME_PAYLOAD";
        second.stringPlaintextLeaks = 10;
        second.stringPlaintextLeakOccurrences = 20;
        second.stringRuntimePlaintextLeaks = 10;
        second.stringRuntimePlaintextLeakOccurrences = 20;
        second.stringScopedRuntimePlaintextLeaks = 10;
        second.stringScopedRuntimePlaintextLeakOccurrences = 20;
        second.stringGlobalRuntimeFallbackHashesTracked = 30;
        second.stringGlobalRuntimeFallbackPlaintextLeaks = 10;
        second.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = 20;
        second.stringOwnerRuntimePlaintextCollisions = 20;
        second.stringOwnerRuntimePlaintextCollisionOccurrences = 30;
        second.stringGlobalRuntimePlaintextCollisions = 30;
        second.stringGlobalRuntimePlaintextCollisionOccurrences = 40;
        second.stringTargetClassesResolved = 50;
        second.stringTargetClassesScanned = 40;
        second.stringTargetMethodsResolved = 70;
        second.stringTargetMethodsScanned = 60;
        second.stringTargetFieldsResolved = 30;
        second.stringTargetFieldsScanned = 20;
        second.stringR8MappedMethodSites = 10;
        second.stringR8RemovedMethodSites = 20;
        second.stringR8IdentityMethodSites = 30;
        second.stringR8FallbackMethodSites = 40;
        second.stringR8MappedFieldProvenance = 50;
        second.stringR8RemovedFieldProvenance = 60;
        second.stringR8IdentityFieldProvenance = 70;
        second.stringR8FallbackFieldProvenance = 80;
        second.stringRemovedOriginalSiteHashesTracked = 90;
        second.stringIdentityFieldProvenanceResolved = 100;
        second.stringIdentityFieldProvenanceScanned = 90;
        second.stringWholePoolPlaintextCollisions = 30;
        second.stringWholePoolPlaintextCollisionOccurrences = 40;
        second.stringConstStringReferencesScanned = 50;
        second.stringStaticStringValuesScanned = 60;
        second.stringAnnotationStringValuesScanned = 70;
        second.stringCallSiteStringValuesScanned = 80;

        ObfuscatorStats aggregate = new ObfuscatorStats();
        aggregate.mergeFrom(new ObfuscatorStats()); // CFG-only/default stats must not change mode.
        aggregate.mergeFrom(first);
        aggregate.mergeFrom(second);
        assertTrue(aggregate.stringPlaintextVerified);
        assertEquals("RUNTIME_PAYLOAD", aggregate.stringPlaintextGateMode);
        assertEquals(11, aggregate.stringPlaintextLeaks);
        assertEquals(22, aggregate.stringPlaintextLeakOccurrences);
        assertEquals(11, aggregate.stringRuntimePlaintextLeaks);
        assertEquals(22, aggregate.stringRuntimePlaintextLeakOccurrences);
        assertEquals(11, aggregate.stringScopedRuntimePlaintextLeaks);
        assertEquals(22, aggregate.stringScopedRuntimePlaintextLeakOccurrences);
        assertEquals(33, aggregate.stringGlobalRuntimeFallbackHashesTracked);
        assertEquals(11, aggregate.stringGlobalRuntimeFallbackPlaintextLeaks);
        assertEquals(22, aggregate.stringGlobalRuntimeFallbackPlaintextLeakOccurrences);
        assertEquals(22, aggregate.stringOwnerRuntimePlaintextCollisions);
        assertEquals(33, aggregate.stringOwnerRuntimePlaintextCollisionOccurrences);
        assertEquals(33, aggregate.stringGlobalRuntimePlaintextCollisions);
        assertEquals(44, aggregate.stringGlobalRuntimePlaintextCollisionOccurrences);
        assertEquals(55, aggregate.stringTargetClassesResolved);
        assertEquals(44, aggregate.stringTargetClassesScanned);
        assertEquals(77, aggregate.stringTargetMethodsResolved);
        assertEquals(66, aggregate.stringTargetMethodsScanned);
        assertEquals(33, aggregate.stringTargetFieldsResolved);
        assertEquals(22, aggregate.stringTargetFieldsScanned);
        assertEquals(11, aggregate.stringR8MappedMethodSites);
        assertEquals(22, aggregate.stringR8RemovedMethodSites);
        assertEquals(33, aggregate.stringR8IdentityMethodSites);
        assertEquals(44, aggregate.stringR8FallbackMethodSites);
        assertEquals(55, aggregate.stringR8MappedFieldProvenance);
        assertEquals(66, aggregate.stringR8RemovedFieldProvenance);
        assertEquals(77, aggregate.stringR8IdentityFieldProvenance);
        assertEquals(88, aggregate.stringR8FallbackFieldProvenance);
        assertEquals(99, aggregate.stringRemovedOriginalSiteHashesTracked);
        assertEquals(110, aggregate.stringIdentityFieldProvenanceResolved);
        assertEquals(99, aggregate.stringIdentityFieldProvenanceScanned);
        assertEquals(33, aggregate.stringWholePoolPlaintextCollisions);
        assertEquals(44, aggregate.stringWholePoolPlaintextCollisionOccurrences);
        assertEquals(55, aggregate.stringConstStringReferencesScanned);
        assertEquals(66, aggregate.stringStaticStringValuesScanned);
        assertEquals(77, aggregate.stringAnnotationStringValuesScanned);
        assertEquals(88, aggregate.stringCallSiteStringValuesScanned);

        ObfuscatorStats strict = new ObfuscatorStats();
        strict.stringPlaintextVerified = true;
        strict.stringPlaintextGateMode = "STRICT_WHOLE_POOL";
        aggregate.mergeFrom(strict);
        assertEquals("MIXED", aggregate.stringPlaintextGateMode);
    }

    @Test
    public void aggregatesLibraryPayloadDiagnosticsAndPreservesItsGateMode() {
        ObfuscatorStats first = new ObfuscatorStats();
        first.stringPlaintextVerified = true;
        first.stringPlaintextGateMode = "LIBRARY_JVM_RUNTIME_PAYLOAD";
        first.stringPlaintextLeaks = 1;
        first.stringRuntimePlaintextLeaks = 1;
        first.stringWholePoolPlaintextCollisions = 3;
        first.stringConstStringReferencesScanned = 4;
        first.stringStaticStringValuesScanned = 5;
        first.stringAnnotationStringValuesScanned = 6;
        first.stringCallSiteStringValuesScanned = 7;

        ObfuscatorStats second = new ObfuscatorStats();
        second.stringPlaintextVerified = true;
        second.stringPlaintextGateMode = "LIBRARY_JVM_RUNTIME_PAYLOAD";
        second.stringPlaintextLeaks = 10;
        second.stringRuntimePlaintextLeaks = 10;
        second.stringWholePoolPlaintextCollisions = 30;
        second.stringConstStringReferencesScanned = 40;
        second.stringStaticStringValuesScanned = 50;
        second.stringAnnotationStringValuesScanned = 60;
        second.stringCallSiteStringValuesScanned = 70;

        ObfuscatorStats aggregate = new ObfuscatorStats();
        aggregate.mergeFrom(first);
        aggregate.mergeFrom(second);
        assertEquals("LIBRARY_JVM_RUNTIME_PAYLOAD", aggregate.stringPlaintextGateMode);
        assertEquals(11, aggregate.stringPlaintextLeaks);
        assertEquals(11, aggregate.stringRuntimePlaintextLeaks);
        assertEquals(33, aggregate.stringWholePoolPlaintextCollisions);
        assertEquals(44, aggregate.stringConstStringReferencesScanned);
        assertEquals(55, aggregate.stringStaticStringValuesScanned);
        assertEquals(66, aggregate.stringAnnotationStringValuesScanned);
        assertEquals(77, aggregate.stringCallSiteStringValuesScanned);
    }

    @Test
    public void eachOutcomeIsCountedExactlyOnceAndJsonIsWritten() throws Exception {
        ObfuscatorStats stats = new ObfuscatorStats();
        stats.methodsScanned = 2;
        stats.recordOutcome(new TransformationOutcome(TransformationOutcome.Mode.REORDERED,
                TransformationOutcome.Reason.VERIFIER_RISK_REORDER,
                "cfg-reorder-symbol-switch", false, 1,
                1, 6, 64, 58, 64));
        stats.recordOutcome(TransformationOutcome.skipped(TransformationOutcome.Reason.TOO_SMALL));
        stats.methodsObfuscated = 1;
        stats.methodsSkippedNotIncluded = 17;
        stats.cfgResolvedClassWideOwners = 18;
        stats.cfgResolvedMemberOnlyOwners = 2;
        stats.cfgResolvedMemberMethods = 3;
        stats.cfgRequiredMethodsResolved = 2;
        stats.cfgRequiredMethodsScanned = 2;
        stats.cfgRequiredMethodsObfuscated = 2;
        stats.stringUnsupportedConstants = 2;
        stats.stringSkippedWhitespace = 21;
        stats.stringSkippedTooLarge = 22;
        stats.stringSkippedInvalidUnicode = 23;
        stats.stringSkippedFiltered = 24;
        stats.stringPlaintextGateMode = "RUNTIME_PAYLOAD";
        stats.stringRuntimePlaintextLeaks = 3;
        stats.stringRuntimePlaintextLeakOccurrences = 4;
        stats.stringScopedRuntimePlaintextLeaks = 3;
        stats.stringScopedRuntimePlaintextLeakOccurrences = 4;
        stats.stringGlobalRuntimeFallbackHashesTracked = 5;
        stats.stringGlobalRuntimeFallbackPlaintextLeaks = 2;
        stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = 3;
        stats.stringOwnerRuntimePlaintextCollisions = 9;
        stats.stringOwnerRuntimePlaintextCollisionOccurrences = 10;
        stats.stringGlobalRuntimePlaintextCollisions = 11;
        stats.stringGlobalRuntimePlaintextCollisionOccurrences = 12;
        stats.stringTargetClassesResolved = 13;
        stats.stringTargetClassesScanned = 10;
        stats.stringTargetMethodsResolved = 14;
        stats.stringTargetMethodsScanned = 9;
        stats.stringTargetFieldsResolved = 8;
        stats.stringTargetFieldsScanned = 7;
        stats.stringR8MappedMethodSites = 21;
        stats.stringR8RemovedMethodSites = 22;
        stats.stringR8IdentityMethodSites = 23;
        stats.stringR8FallbackMethodSites = 24;
        stats.stringR8MappedFieldProvenance = 25;
        stats.stringR8RemovedFieldProvenance = 26;
        stats.stringR8IdentityFieldProvenance = 27;
        stats.stringR8FallbackFieldProvenance = 28;
        stats.stringRemovedOriginalSiteHashesTracked = 29;
        stats.stringIdentityFieldProvenanceResolved = 30;
        stats.stringIdentityFieldProvenanceScanned = 30;
        stats.stringWholePoolPlaintextCollisions = 5;
        stats.stringWholePoolPlaintextCollisionOccurrences = 6;
        stats.stringConstStringReferencesScanned = 7;
        stats.stringStaticStringValuesScanned = 8;
        stats.stringAnnotationStringValuesScanned = 9;
        stats.stringCallSiteStringValuesScanned = 10;
        stats.originalDexBytes = 100;
        stats.outputDexBytes = 125;
        assertEquals(1, stats.methodsReordered);
        assertEquals(1, stats.methodsSkipped());
        assertEquals(0, stats.methodsSkippedUnsupported);

        Path report = Files.createTempFile("dex-cfg-report-", ".json");
        try {
            ObfuscationReportWriter.write(report.toFile(), "test", new ObfuscatorConfig(), stats);
            String json = new String(Files.readAllBytes(report), StandardCharsets.UTF_8);
            assertTrue(json.contains("\"methodsSkipped\": 1"));
            assertTrue(json.contains("\"notIncluded\": 17"));
            assertTrue(json.contains("\"cfgResolvedClassWideOwners\": 18"));
            assertTrue(json.contains("\"cfgResolvedMemberOnlyOwners\": 2"));
            assertTrue(json.contains("\"cfgResolvedMemberMethods\": 3"));
            assertTrue(json.contains("\"cfgRequiredMethodsResolved\": 2"));
            assertTrue(json.contains("\"cfgRequiredMethodsScanned\": 2"));
            assertTrue(json.contains("\"cfgRequiredMethodsObfuscated\": 2"));
            assertTrue(json.contains("\"obfuscatedRatio\": 0.5"));
            assertTrue(json.contains("\"tooSmall\": 1"));
            assertTrue(json.contains("\"minObfuscatedMethods\": 0"));
            assertTrue(json.contains("\"minFlattenedMethods\": 0"));
            assertTrue(json.contains("\"maxSizeIncreasePercent\": 100.0"));
            assertTrue(json.contains("\"maxSkippedStrings\": 2147483647"));
            assertTrue(json.contains("\"maxUnsafeSkippedStrings\": 2147483647"));
            assertTrue(json.contains("\"maxFilteredStrings\": 2147483647"));
            assertTrue(json.contains("\"failOnUnsupportedStringConstants\": false"));
            assertTrue(json.contains("\"failOnUnprotectedDecryptor\": false"));
            assertTrue(json.contains("\"sizeIncreasePercent\": 25.0"));
            assertTrue(json.contains("\"schemaVersion\": 10"));
            assertTrue(json.contains("\"evidence\": {"));
            assertTrue(json.contains("\"stringEncryptionEnabled\": false"));
            assertTrue(json.contains("\"stringCoverageStatus\": \"DISABLED\""));
            assertTrue(json.contains("\"stringUnsupportedConstants\": 2"));
            assertTrue(json.contains("\"stringSkippedWhitespace\": 21"));
            assertTrue(json.contains("\"stringSkippedTooLarge\": 22"));
            assertTrue(json.contains("\"stringSkippedInvalidUnicode\": 23"));
            assertTrue(json.contains("\"stringSkippedFiltered\": 24"));
            assertTrue(json.contains("\"stringPlaintextVerified\": false"));
            assertTrue(json.contains("\"stringPlaintextGateMode\": \"RUNTIME_PAYLOAD\""));
            assertTrue(json.contains("\"stringPlaintextLeaks\": 0"));
            assertTrue(json.contains("\"stringRuntimePlaintextLeaks\": 3"));
            assertTrue(json.contains("\"stringRuntimePlaintextLeakOccurrences\": 4"));
            assertTrue(json.contains("\"stringScopedRuntimePlaintextLeaks\": 3"));
            assertTrue(json.contains("\"stringScopedRuntimePlaintextLeakOccurrences\": 4"));
            assertTrue(json.contains("\"stringGlobalRuntimeFallbackHashesTracked\": 5"));
            assertTrue(json.contains("\"stringGlobalRuntimeFallbackPlaintextLeaks\": 2"));
            assertTrue(json.contains("\"stringGlobalRuntimeFallbackPlaintextLeakOccurrences\": 3"));
            assertTrue(json.contains("\"stringOwnerRuntimePlaintextCollisions\": 9"));
            assertTrue(json.contains("\"stringOwnerRuntimePlaintextCollisionOccurrences\": 10"));
            assertTrue(json.contains("\"stringGlobalRuntimePlaintextCollisions\": 11"));
            assertTrue(json.contains("\"stringGlobalRuntimePlaintextCollisionOccurrences\": 12"));
            assertTrue(json.contains("\"stringTargetClassesResolved\": 13"));
            assertTrue(json.contains("\"stringTargetClassesScanned\": 10"));
            assertTrue(json.contains("\"stringTargetMethodsResolved\": 14"));
            assertTrue(json.contains("\"stringTargetMethodsScanned\": 9"));
            assertTrue(json.contains("\"stringTargetFieldsResolved\": 8"));
            assertTrue(json.contains("\"stringTargetFieldsScanned\": 7"));
            assertTrue(json.contains("\"stringR8MappedMethodSites\": 21"));
            assertTrue(json.contains("\"stringR8RemovedMethodSites\": 22"));
            assertTrue(json.contains("\"stringR8IdentityMethodSites\": 23"));
            assertTrue(json.contains("\"stringR8FallbackMethodSites\": 24"));
            assertTrue(json.contains("\"stringR8MappedFieldProvenance\": 25"));
            assertTrue(json.contains("\"stringR8RemovedFieldProvenance\": 26"));
            assertTrue(json.contains("\"stringR8IdentityFieldProvenance\": 27"));
            assertTrue(json.contains("\"stringR8FallbackFieldProvenance\": 28"));
            assertTrue(json.contains("\"stringRemovedOriginalSiteHashesTracked\": 29"));
            assertTrue(json.contains("\"stringIdentityFieldProvenanceResolved\": 30"));
            assertTrue(json.contains("\"stringIdentityFieldProvenanceScanned\": 30"));
            assertTrue(json.contains("\"stringWholePoolPlaintextCollisions\": 5"));
            assertTrue(json.contains("\"stringWholePoolPlaintextCollisionOccurrences\": 6"));
            assertTrue(json.contains("\"stringConstStringReferencesScanned\": 7"));
            assertTrue(json.contains("\"stringStaticStringValuesScanned\": 8"));
            assertTrue(json.contains("\"stringAnnotationStringValuesScanned\": 9"));
            assertTrue(json.contains("\"stringCallSiteStringValuesScanned\": 10"));
            assertTrue(json.contains("\"switchesPadded\": 1"));
            assertTrue(json.contains("\"switchCasesBefore\": 6"));
            assertTrue(json.contains("\"switchCasesAfter\": 64"));
            assertTrue(json.contains("\"fakeSwitchCases\": 58"));
            assertTrue(json.contains("\"symbolSwitchCases\": 64"));
            assertTrue(json.contains("\"regionalDispatchers\": 0"));
            assertTrue(json.contains("\"reachableAliasCases\": 0"));
        } finally {
            Files.deleteIfExists(report);
        }
    }

    @Test
    public void requiredCoverageIsProvedPerFinalKeyNotByAggregateCounts() {
        ObfuscatorStats stats = new ObfuscatorStats();
        stats.methodReports.add(requiredReport("LA;", "x", "flattened"));
        stats.methodReports.add(requiredReport("LA;", "x", "reordered"));
        Set<String> required = new java.util.LinkedHashSet<>(Arrays.asList("A->x", "B->y"));
        assertFalse(stats.hasCompleteRequiredMethodCoverage(required));

        stats.methodReports.add(requiredReport("LB;", "y", "skipped"));
        assertFalse(stats.hasCompleteRequiredMethodCoverage(required));

        stats.methodReports.clear();
        stats.methodReports.add(requiredReport("LA;", "x", "flattened"));
        stats.methodReports.add(requiredReport("LB;", "y", "reordered"));
        assertTrue(stats.hasCompleteRequiredMethodCoverage(required));
    }

    private static MethodReport requiredReport(String owner, String name, String mode) {
        return MethodReport.restore("classes.dex", owner, name, "()V", mode,
                "flatten_safe", "regional", 1, 2, 1, 2, 1, 3,
                false, false, false, false, 2, 0, 0, 0,
                0, 0, 1, 0, 2);
    }

    @Test
    public void rejectsPostTransformCodeUnitExplosion() {
        MethodImplementationBuilder before = new MethodImplementationBuilder(1);
        before.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        before.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        before.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));
        before.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        MethodImplementationBuilder after = new MethodImplementationBuilder(1);
        for (int i = 0; i < 8_300; i++) {
            after.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        }
        after.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        ObfuscatorConfig config = new ObfuscatorConfig();
        config.depth = 2;
        try {
            PostTransformBudget.verify(before.getMethodImplementation(),
                    after.getMethodImplementation(), config);
            fail("oversized transformed method should be rejected");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("code-unit budget exceeded"));
        }
    }

    @Test
    public void rejectsMoveResultWithoutProducer() throws Exception {
        MethodImplementationBuilder body = new MethodImplementationBuilder(1);
        body.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        body.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ImmutableMethod method = new ImmutableMethod("Lcom/example/Invalid;", "bad",
                Collections.emptyList(), "V", AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), body.getMethodImplementation());
        ImmutableClassDef classDef = new ImmutableClassDef("Lcom/example/Invalid;",
                AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", Collections.emptyList(),
                null, Collections.emptySet(), Collections.emptyList(), Collections.emptyList(),
                Collections.singleton(method), Collections.emptySet());
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(classDef);
        Path dex = Files.createTempFile("dex-cfg-invalid-", ".dex");
        try {
            pool.writeTo(new FileDataStore(dex.toFile()));
            try {
                DexStructuralVerifier.verify(dex.toFile());
                fail("invalid move-result should be rejected");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().toLowerCase(java.util.Locale.US)
                        .contains("move_result"));
            }
        } finally {
            Files.deleteIfExists(dex);
        }
    }

    @Test
    public void acceptsHandlerThatIgnoresCaughtException() throws Exception {
        MethodImplementationBuilder body = new MethodImplementationBuilder(2);
        com.android.tools.smali.dexlib2.builder.Label start = body.getLabel("Start");
        com.android.tools.smali.dexlib2.builder.Label end = body.getLabel("End");
        com.android.tools.smali.dexlib2.builder.Label handler = body.getLabel("Handler");
        body.addLabel("Start");
        body.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        body.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        body.addInstruction(new BuilderInstruction12x(Opcode.DIV_INT_2ADDR, 0, 1));
        body.addLabel("End");
        body.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        body.addLabel("Handler");
        // 合法：catch 后不读取异常对象，因此无需 move-exception。
        body.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        body.addCatch(new com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference(
                "Ljava/lang/ArithmeticException;"), start, end, handler);

        ImmutableMethod method = new ImmutableMethod("Lcom/example/Ignore;", "ignore",
                Collections.emptyList(), "V", AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), body.getMethodImplementation());
        ImmutableClassDef classDef = new ImmutableClassDef("Lcom/example/Ignore;",
                AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", Collections.emptyList(),
                null, Collections.emptySet(), Collections.emptyList(), Collections.emptyList(),
                Collections.singleton(method), Collections.emptySet());
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(classDef);
        Path dex = Files.createTempFile("dex-cfg-ignore-handler-", ".dex");
        try {
            pool.writeTo(new FileDataStore(dex.toFile()));
            DexStructuralVerifier.verify(dex.toFile());
        } finally {
            Files.deleteIfExists(dex);
        }
    }

    @Test
    public void acceptsDex039InvokePolymorphicFollowedByMoveResultWide() throws Exception {
        MethodImplementationBuilder body = new MethodImplementationBuilder(5);
        body.addInstruction(new BuilderInstruction45cc(Opcode.INVOKE_POLYMORPHIC,
                5, 0, 1, 2, 3, 4,
                new ImmutableMethodReference("Ljava/lang/invoke/MethodHandle;", "invokeExact",
                        Collections.singletonList("[Ljava/lang/Object;"), "Ljava/lang/Object;"),
                new ImmutableMethodProtoReference(java.util.Arrays.asList("J", "J"), "J")));
        body.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 0));
        body.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));

        ImmutableMethod method = new ImmutableMethod("Lcom/example/Polymorphic;", "invoke",
                java.util.Arrays.asList(
                        new ImmutableMethodParameter("Ljava/lang/invoke/MethodHandle;", null, null),
                        new ImmutableMethodParameter("J", null, null),
                        new ImmutableMethodParameter("J", null, null)), "J",
                AccessFlags.STATIC.getValue(), Collections.emptySet(), Collections.emptySet(),
                body.getMethodImplementation());
        ImmutableClassDef classDef = new ImmutableClassDef("Lcom/example/Polymorphic;",
                AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", Collections.emptyList(),
                null, Collections.emptySet(), Collections.emptyList(), Collections.emptyList(),
                Collections.singleton(method), Collections.emptySet());
        DexPool pool = new DexPool(Opcodes.forDexVersion(39));
        pool.internClass(classDef);
        Path dex = Files.createTempFile("dex-cfg-039-polymorphic-", ".dex");
        try {
            pool.writeTo(new FileDataStore(dex.toFile()));
            assertTrue(new String(Files.readAllBytes(dex), 0, 8, StandardCharsets.US_ASCII)
                    .startsWith("dex\n039"));
            DexStructuralVerifier.verify(dex.toFile());
        } finally {
            Files.deleteIfExists(dex);
        }
    }
}
