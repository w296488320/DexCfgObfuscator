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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ReportAndStructuralVerifierTest {
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
            assertTrue(json.contains("\"obfuscatedRatio\": 0.5"));
            assertTrue(json.contains("\"tooSmall\": 1"));
            assertTrue(json.contains("\"minObfuscatedMethods\": 0"));
            assertTrue(json.contains("\"maxSizeIncreasePercent\": 100.0"));
            assertTrue(json.contains("\"sizeIncreasePercent\": 25.0"));
            assertTrue(json.contains("\"schemaVersion\": 3"));
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
