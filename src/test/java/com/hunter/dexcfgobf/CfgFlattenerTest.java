package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderArrayPayload;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderPackedSwitchPayload;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21t;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction11n;

import org.junit.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * CfgFlattener 正确性单测：不依赖真机，构造带分支的方法实现，混淆后校验：
 *   1) 混淆成功（返回非 null）且能被 dexlib2 重新解析（结构合法、所有 Label 可解析）；
 *   2) 原始（非新增）opcode 直方图被完整保留（新增的只能是 GOTO/GOTO_16/GOTO_32）；
 *   3) 语义等价：从入口开始按 goto/条件跳转“执行”混淆后的方法，得到的原始指令线性序，
 *      与原方法逐指令一致（这是“不影响原始逻辑”的可判定近似）。
 */
public class CfgFlattenerTest {

    private CfgFlattener newFlattener(ObfuscatorStats stats) {
        ObfuscatorConfig cfg = new ObfuscatorConfig();
        cfg.depth = 2;
        return new CfgFlattener(cfg, ObfuscatorLogger.STDOUT, stats);
    }

    /**
     * 构造含条件分支 + 多基本块的方法：
     *   0: const/4 v0, 0
     *   1: if-eqz v0, L_a       ; -> 4
     *   2: const/4 v0, 1
     *   3: return-void
     *   4: (L_a) const/4 v0, 2
     *   5: return-void
     */
    private MutableMethodImplementation buildSample() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label la = b.getLabel("La");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));       // 0
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, la));       // 1 -> La
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));       // 2
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));         // 3
        b.addLabel("La");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));       // 4 La
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));         // 5
        return (MutableMethodImplementation) b.getMethodImplementation();
    }

    @Test
    public void flattensAndPreservesSemantics() {
        MutableMethodImplementation src = buildSample();
        Map<Opcode, Integer> before = opcodeHistogram(src);

        ObfuscatorStats stats = new ObfuscatorStats();
        CfgFlattener flattener = newFlattener(stats);
        MethodImplementation out = flattener.flatten(fakeMethod(), src);

        assertNotNull("expected flattening to succeed on multi-block method", out);

        // 混淆后可被 dexlib2 重新构造（结构合法、所有 Label 可解析）。
        MutableMethodImplementation reparsed = new MutableMethodImplementation(out);
        assertTrue("flattened body should be larger (dispatcher+glue)",
                reparsed.getInstructions().size() > before.values().stream().mapToInt(Integer::intValue).sum());

        // 平坦化特征：出现多个区域 sparse-switch dispatcher。
        Map<Opcode, Integer> after = opcodeHistogram(out);
        assertTrue("expected a switch dispatcher",
                after.getOrDefault(Opcode.PACKED_SWITCH, 0)
                        + after.getOrDefault(Opcode.SPARSE_SWITCH, 0) >= 1);
        TransformationOutcome outcome = flattener.getLastOutcome();
        assertEquals("MEDIUM should split a multi-block method into three regions",
                3, outcome.dispatcherRegions);
        assertTrue("reachable alias cases must replace dead decoys",
                outcome.reachableAliasCases >= 2);
        assertEquals("state must be represented by two XOR shares",
                2, outcome.stateShareRegisters);
        assertEquals("all regional dispatchers use random sparse keys",
                outcome.dispatcherRegions,
                after.getOrDefault(Opcode.SPARSE_SWITCH, 0).intValue());
        assertEquals(0, after.getOrDefault(Opcode.PACKED_SWITCH, 0).intValue());
        assertEquals("strong flattening adds shareA/shareB/work/route registers",
                src.getRegisterCount() + 4, out.getRegisterCount());

        // 语义等价：解释执行原方法 vs 平坦化方法，比较“真实指令”访问序列。
        // 平坦化后寄存器整体 +4（两个 state share + work + route）。
        List<String> origTrace = shiftRegsInTrace(simulate(src, 0), 4);
        regFile.clear();
        List<String> obfTrace = simulate(new MutableMethodImplementation(out), 4);
        System.out.println("ORIG TRACE(+4) = " + origTrace);
        System.out.println("OBF  TRACE     = " + obfTrace);
        assertEquals("execution trace (real insns) must be identical", origTrace, obfTrace);
    }

    @Test
    public void skipsTinyMethod() {
        MutableMethodImplementation tiny = new MutableMethodImplementation(1);
        tiny.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(fakeMethod(), tiny);
        assertEquals("tiny method must be left unchanged", null, out);
        assertTrue(stats.methodsSkippedTooSmall >= 1);
    }

    @Test
    public void upgradesConst4WhenFourRegisterShiftCrossesV15() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(13);
        Label yes = b.getLabel("HighYes");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 12, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 12, yes));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 12, 1));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("HighYes");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 12, 2));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(fakeMethod(), b.getMethodImplementation());
        assertNotNull(out);
        assertEquals(1, stats.methodsFlattened);
        boolean sawV16Const = false;
        for (Instruction instruction : out.getInstructions()) {
            if (instruction.getOpcode() == Opcode.CONST_16
                    && ((com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction)
                    instruction).getRegisterA() == 16) {
                sawV16Const = true;
            }
        }
        assertTrue("const/4 v12 must upgrade to const/16 v16", sawV16Const);
    }

    @Test
    public void booleanReturnNeverUsesPlainIntStrongFlattening() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label falseCase = b.getLabel("False");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, falseCase));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("False");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));

        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(
                fakeMethod("returnsBoolean", "Z"), b.getMethodImplementation());

        assertNotNull("boolean result should retain CFG through safe reorder", out);
        assertEquals(0, stats.methodsFlattened);
        assertEquals(1, stats.methodsReordered);
    }

    /** 构造一个会抛 ArithmeticException、由本方法 catch 的真实异常控制流。 */
    private MutableMethodImplementation buildTryCatchSample() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(3);
        Label tryStart = b.getLabel("TryStart");
        Label tryEnd = b.getLabel("TryEnd");
        Label handler = b.getLabel("Handler");
        b.addLabel("TryStart");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.DIV_INT_2ADDR, 0, 1));
        b.addLabel("TryEnd");
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("Handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, -1));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addCatch(new com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference(
                "Ljava/lang/ArithmeticException;"), tryStart, tryEnd, handler);
        return (MutableMethodImplementation) b.getMethodImplementation();
    }

    @Test
    public void preservesTryCatchTableAndMoveExceptionHandler() {
        ObfuscatorConfig cfg = new ObfuscatorConfig();
        cfg.depth = 2;
        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = new CfgFlattener(cfg, ObfuscatorLogger.STDOUT, stats)
                .flatten(fakeMethod(), buildTryCatchSample());

        assertNotNull("try/catch method should be obfuscated", out);
        MutableMethodImplementation reparsed = new MutableMethodImplementation(out);
        assertFalse("try table must survive register shifting and flattening", reparsed.getTryBlocks().isEmpty());
        for (com.android.tools.smali.dexlib2.iface.TryBlock<? extends com.android.tools.smali.dexlib2.iface.ExceptionHandler> tb
                : reparsed.getTryBlocks()) {
            for (com.android.tools.smali.dexlib2.iface.ExceptionHandler h : tb.getExceptionHandlers()) {
                int handlerIndex = ((com.android.tools.smali.dexlib2.builder.BuilderExceptionHandler) h)
                        .getHandler().getLocation().getIndex();
                assertEquals("handler entry must remain move-exception",
                        Opcode.MOVE_EXCEPTION, reparsed.getInstructions().get(handlerIndex).getOpcode());
            }
        }
        assertEquals("try/catch must not gain dispatcher verifier edges", 0, stats.methodsFlattened);
        assertTrue("try/catch should use CFG-preserving reorder", stats.methodsReordered >= 1);
    }

    @Test
    public void honorsTryCatchSkipSwitch() {
        ObfuscatorConfig cfg = new ObfuscatorConfig();
        cfg.skipMethodsWithTryCatch = true;
        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = new CfgFlattener(cfg, ObfuscatorLogger.STDOUT, stats)
                .flatten(fakeMethod(), buildTryCatchSample());
        assertEquals(null, out);
        assertEquals(1, stats.methodsSkippedTryCatch);
    }

    @Test
    public void reorderedFallbackIsIdempotent() {
        ObfuscatorStats firstStats = new ObfuscatorStats();
        MethodImplementation once = newFlattener(firstStats)
                .flatten(fakeMethod("<init>", "V", 0), buildSample());
        assertNotNull("constructor should use the verifier-safe reorder fallback", once);
        assertEquals(1, firstStats.methodsReordered);

        ObfuscatorStats secondStats = new ObfuscatorStats();
        MethodImplementation twice = newFlattener(secondStats)
                .flatten(fakeMethod("<init>"), once);
        assertEquals("an already reordered body must not be reordered again", null, twice);
        assertEquals(1, secondStats.methodsSkippedAlreadyObfuscated);
    }

    /**
     * 复现启动崩溃的根因：同一局部寄存器在互不相交的生命周期里先后承载 byte[] 和 String。
     * 原 CFG 合法，但 dispatcher 会给各块增加汇合边，使 ART 报 String/byte[] VerifyError。
     */
    @Test
    public void referenceRegisterReuseNeverUsesStrongFlattening() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(2);
        Label bytes = b.getLabel("Bytes");
        Label done = b.getLabel("Done");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, bytes));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1,
                new com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference("direct")));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, done));
        b.addLabel("Bytes");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0,
                new com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference("[B")));
        // 模拟 byte[] 经解密后重新写回同一寄存器为 String。
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1,
                new com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference("converted")));
        b.addLabel("Done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));

        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(
                fakeMethod("referenceReuse", "Ljava/lang/String;"), b.getMethodImplementation());

        assertNotNull("reference-bearing methods should use CFG-preserving reorder", out);
        Map<Opcode, Integer> histogram = opcodeHistogram(out);
        assertEquals(0, histogram.getOrDefault(Opcode.PACKED_SWITCH, 0).intValue());
        assertEquals(0, histogram.getOrDefault(Opcode.SPARSE_SWITCH, 0).intValue());
        assertEquals(0, stats.methodsFlattened);
        assertEquals(1, stats.methodsReordered);
        assertEquals(1, stats.reorderedVerifierRisk);
    }

    @Test
    public void resolvesPostR8NamesWithoutIncludingRepackagedThirdPartyClasses() throws Exception {
        Path mapping = Files.createTempFile("dex-cfg-obf-r8-", ".txt");
        try {
            Files.write(mapping, java.util.Arrays.asList(
                    "com.example.Secret -> YouAreLoser.a:",
                    "    1:1:void run():1:1 -> a",
                    "third.party.Library -> YouAreLoser.b:",
                    "com.example.Kept -> com.example.Kept:",
                    "com.example.hunter.NativeEngine -> com.example.hunter.NativeEngine:"
            ), StandardCharsets.UTF_8);
            ObfuscatorConfig cfg = new ObfuscatorConfig();
            cfg.includePrefixes.add("com/example");
            cfg.excludePrefixes.add("com/example/hunter/NativeEngine");

            assertEquals(2, R8MappingResolver.apply(mapping.toFile(), cfg));
            assertTrue(cfg.shouldProcessClass("LYouAreLoser/a;"));
            assertTrue(cfg.shouldProcessClass("Lcom/example/Kept;"));
            assertFalse(cfg.shouldProcessClass("LYouAreLoser/b;"));
            assertFalse(cfg.shouldProcessClass("Lcom/example/hunter/NativeEngine;"));
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    /**
     * 构造含 fill-array-data 的方法（StringFog 加密字符串后的典型形态：new byte[]{...}）：
     *   0: const/4 v0, 0
     *   1: if-eqz v0, L_a        ; -> 4
     *   2: const/4 v0, 3
     *   3: new-array v0, v0, [B
     *   4: fill-array-data v0, :data
     *   5: return-void
     *   6: (L_a) const/4 v0, 1
     *   7: return-void
     *   :data .array-data 1  { 10 20 30 }
     * 关键校验点：平坦化后 array-data payload 被重定位到方法尾部、fill-array-data 目标仍解析到它，
     * 整体可被 dexlib2 重新解析（合法 dex）。这直接对应 repairFirebaseDataStoreDirs 这类“带字符串
     * 字面量、旧逻辑被 payload 守卫整段跳过”的方法现在能被平坦化。
     */
    private MutableMethodImplementation buildArrayDataSample() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label la = b.getLabel("La");
        Label data = b.getLabel("Data");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));                 // 0
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, la));                 // 1 -> La
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 3));                 // 2
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0,
                new com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference("[B"))); // 3
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 0, data));      // 4 -> :data
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));                   // 5
        b.addLabel("La");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));                 // 6 La
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));                   // 7
        b.addLabel("Data");
        b.addInstruction(new BuilderArrayPayload(1, java.util.Arrays.asList(
                (Number) (byte) 10, (byte) 20, (byte) 30)));                              // :data
        return (MutableMethodImplementation) b.getMethodImplementation();
    }

    @Test
    public void reordersMethodWithFillArrayDataAndRelocatesPayload() {
        MutableMethodImplementation src = buildArrayDataSample();
        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(fakeMethod(), src);

        assertNotNull("array payload method should use CFG-preserving reorder", out);
        assertEquals(0, stats.methodsFlattened);
        assertEquals(1, stats.methodsReordered);
        MutableMethodImplementation rebuilt = new MutableMethodImplementation(out);
        boolean checkedTarget = false;
        for (com.android.tools.smali.dexlib2.builder.BuilderInstruction instruction : rebuilt.getInstructions()) {
            if (instruction.getOpcode() == Opcode.FILL_ARRAY_DATA) {
                int target = ((com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction) instruction)
                        .getTarget().getLocation().getIndex();
                assertEquals(Opcode.ARRAY_PAYLOAD, rebuilt.getInstructions().get(target).getOpcode());
                checkedTarget = true;
            }
        }
        assertTrue("fill-array-data must target relocated payload", checkedTarget);
    }

    /**
     * 复现 d8 真实布局：array-data payload 前有对齐 nop、且方法可执行区尾部并非紧接 return
     * （fill-array-data 后还有 return，但 payload 与对齐 nop 位于最后 return 之后）。
     * 这会让“首个 payload 之前的对齐 nop”若被当作可执行代码，末块以 nop 落空、后继落到数据区，
     * 触发 stateId[k] 越界。修复后应正常平坦化。
     */
    private MutableMethodImplementation buildArrayDataWithAlignNop() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label la = b.getLabel("La");
        Label d1 = b.getLabel("D1");
        Label d2 = b.getLabel("D2");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));                 // 0
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, la));                 // 1 -> La
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 3));                 // 2
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0,
                new com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference("[B"))); // 3
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 0, d1));        // 4 -> :d1
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));                   // 5
        b.addLabel("La");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 5));                 // 6 La
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0,
                new com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference("[B"))); // 7
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 0, d2));        // 8 -> :d2
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));                   // 9
        // 尾部数据区：对齐 nop + 两个 array-data payload（模拟 d8 布局）。
        b.addInstruction(new BuilderInstruction10x(Opcode.NOP));                           // 10 (align)
        b.addLabel("D1");
        b.addInstruction(new BuilderArrayPayload(1, java.util.Arrays.asList(
                (Number) (byte) 1, (byte) 2, (byte) 3)));                                 // :d1 (3 units, odd)
        b.addInstruction(new BuilderInstruction10x(Opcode.NOP));                           // (align)
        b.addLabel("D2");
        b.addInstruction(new BuilderArrayPayload(1, java.util.Arrays.asList(
                (Number) (byte) 4, (byte) 5, (byte) 6, (byte) 7, (byte) 8)));             // :d2 (5 units)
        return (MutableMethodImplementation) b.getMethodImplementation();
    }

    @Test
    public void reordersAlignedMultipleArrayPayloads() {
        MutableMethodImplementation src = buildArrayDataWithAlignNop();
        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(fakeMethod(), src);

        assertNotNull("multiple aligned payloads should be relocated", out);
        assertEquals(0, stats.methodsFlattened);
        assertEquals(1, stats.methodsReordered);
        Map<Opcode, Integer> histogram = opcodeHistogram(out);
        assertEquals(2, histogram.getOrDefault(Opcode.FILL_ARRAY_DATA, 0).intValue());
        assertEquals(2, histogram.getOrDefault(Opcode.ARRAY_PAYLOAD, 0).intValue());
    }

    @Test
    public void padsOriginalSwitchWithDecompilerVisibleCharacterCases() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(2);
        Label payload = b.getLabel("Payload");
        Label case0 = b.getLabel("Case0");
        Label case1 = b.getLabel("Case1");
        Label done = b.getLabel("Done");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction31t(Opcode.PACKED_SWITCH, 0, payload));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, -1));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, done));
        b.addLabel("Case0");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, done));
        b.addLabel("Case1");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 1));
        b.addLabel("Done");
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("Payload");
        b.addInstruction(new BuilderPackedSwitchPayload(0, java.util.Arrays.asList(case0, case1)));

        ObfuscatorStats stats = new ObfuscatorStats();
        CfgFlattener flattener = newFlattener(stats);
        MethodImplementation out = flattener.flatten(fakeMethod(), b.getMethodImplementation());

        assertNotNull("original switch should use CFG-preserving reorder", out);
        assertEquals(0, stats.methodsFlattened);
        assertEquals(1, stats.methodsReordered);
        MutableMethodImplementation rebuilt = new MutableMethodImplementation(out);
        assertEquals("one independent scratch register must be added", 3, rebuilt.getRegisterCount());
        assertTrue("selector must pass through keyed 32-bit encoding",
                opcodeHistogram(rebuilt).getOrDefault(Opcode.MOVE_FROM16, 0) >= 1
                        && opcodeHistogram(rebuilt).getOrDefault(Opcode.MUL_INT_LIT16, 0) >= 1);
        assertTrue("selector should be explicitly typed as char before dispatch",
                opcodeHistogram(rebuilt).getOrDefault(Opcode.INT_TO_CHAR, 0) >= 1);
        boolean checkedEncoded = false;
        boolean checkedSymbols = false;
        int sparseSwitchCount = 0;
        for (com.android.tools.smali.dexlib2.builder.BuilderInstruction instruction : rebuilt.getInstructions()) {
            if (instruction.getOpcode() == Opcode.SPARSE_SWITCH) {
                sparseSwitchCount++;
                int target = ((com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction) instruction)
                        .getTarget().getLocation().getIndex();
                assertEquals(Opcode.SPARSE_SWITCH_PAYLOAD,
                        rebuilt.getInstructions().get(target).getOpcode());
                com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload padded =
                        (com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload)
                                rebuilt.getInstructions().get(target);
                assertTrue("MEDIUM should pad into the 50..80 range",
                        padded.getSwitchElements().size() >= 50
                                && padded.getSwitchElements().size() <= 80);
                HashSet<Integer> keys = new HashSet<>();
                boolean allVisibleChars = true;
                boolean hasPositive = false;
                boolean hasNegative = false;
                boolean hasExtreme = false;
                for (com.android.tools.smali.dexlib2.iface.instruction.SwitchElement element
                        : padded.getSwitchElements()) {
                    assertTrue("case keys must be unique", keys.add(element.getKey()));
                    int key = element.getKey();
                    allVisibleChars &= key >= 0x20 && key <= 0x7E;
                    hasPositive |= key > 65535;
                    hasNegative |= key < -65535;
                    hasExtreme |= key <= Integer.MIN_VALUE + (1 << 20)
                            || key >= Integer.MAX_VALUE - (1 << 20);
                }
                if (allVisibleChars) {
                    checkedSymbols = true;
                } else {
                    assertFalse("original case 0 must not leak", keys.contains(0));
                    assertFalse("original case 1 must not leak", keys.contains(1));
                    assertTrue("encoded cases should contain positive sparse keys", hasPositive);
                    assertTrue("encoded cases should contain negative sparse keys", hasNegative);
                    assertTrue("encoded cases should contain int-extreme decoys", hasExtreme);
                    checkedEncoded = true;
                }
            }
        }
        assertEquals("encoded + symbol dispatchers expected", 2, sparseSwitchCount);
        assertTrue("rebuilt encoded sparse-switch not found", checkedEncoded);
        assertTrue("rebuilt symbol sparse-switch not found", checkedSymbols);
        TransformationOutcome outcome = flattener.getLastOutcome();
        assertEquals(1, outcome.switchesPadded);
        assertEquals(2, outcome.switchCasesBefore);
        assertTrue(outcome.fakeSwitchCases >= 48);
        assertEquals(outcome.switchCasesAfter, outcome.symbolSwitchCases);
    }

    /**
     * 极简 DEX 解释器：处理 const/4、const/16、if-eqz、goto、packed-switch、return-void。
     * @param regShift 原方法用 0；平坦化方法用 1（因为寄存器整体 +1）。
     * 返回“执行过的真实指令”规范化序列（忽略 dispatcher 的 const/16 vState 与 goto/switch）。
     */
    private List<String> simulate(MutableMethodImplementation impl, int regShift) {
        List<com.android.tools.smali.dexlib2.builder.BuilderInstruction> insns = impl.getInstructions();
        java.util.ArrayList<String> trace = new java.util.ArrayList<>();
        int workReg = regShift; // 原 v0 混淆后是 v1
        int vval = 0;
        int pc = 0;
        int steps = 0;
        // 平坦化方法有“入口预初始化前奏”（把非参寄存器清 0），这些是纯 glue，不计入 trace。
        // 用 hasDispatcher 判断是否为平坦化体；前奏 = 首个 PACKED_SWITCH 之前的所有指令。
        boolean hasDispatcher = false;
        for (com.android.tools.smali.dexlib2.builder.BuilderInstruction bi : insns) {
            if (bi.getOpcode() == Opcode.PACKED_SWITCH || bi.getOpcode() == Opcode.SPARSE_SWITCH) {
                hasDispatcher = true;
                break;
            }
        }
        boolean recording = !hasDispatcher; // 无 dispatcher（原方法）从头记录
        while (pc >= 0 && pc < insns.size() && steps++ < 100000) {
            Instruction insn = insns.get(pc);
            Opcode op = insn.getOpcode();
            if (isGotoFamily(op)) { pc = branchTargetIndex(impl, pc); continue; }
            if (op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH) {
                recording = true; // 前奏结束，开始记录真实指令
                int stateReg = ((com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction)
                        insn).getRegisterA();
                int stateVal = regFile.getOrDefault(stateReg, 0);
                pc = packedSwitchTarget(impl, pc, stateVal);
                continue;
            }
            if (op == Opcode.PACKED_SWITCH_PAYLOAD || op == Opcode.SPARSE_SWITCH_PAYLOAD) {
                break; // 不应顺序执行到 payload
            }
            if (op == Opcode.XOR_INT_LIT16 || op == Opcode.ADD_INT_LIT16
                    || op == Opcode.MUL_INT_LIT16
                    || op == Opcode.AND_INT_LIT16 || op == Opcode.OR_INT_LIT16) {
                // dispatcher 的 state 解密 / scratch 运算：vA = vB op lit16。执行不计入 trace。
                com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22s t22 =
                        (com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22s) insn;
                int a = t22.getRegisterA(), b = t22.getRegisterB(), lit = t22.getNarrowLiteral();
                int bv = regFile.getOrDefault(b, 0);
                int res;
                if (op == Opcode.XOR_INT_LIT16) res = bv ^ lit;
                else if (op == Opcode.AND_INT_LIT16) res = bv & lit;
                else if (op == Opcode.OR_INT_LIT16) res = bv | lit;
                else if (op == Opcode.MUL_INT_LIT16) res = bv * lit;
                else res = bv + lit;
                regFile.put(a, res);
                pc++; continue;
            }
            if (op == Opcode.SHL_INT_LIT8) {
                com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22b t22 =
                        (com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22b) insn;
                regFile.put(t22.getRegisterA(),
                        regFile.getOrDefault(t22.getRegisterB(), 0) << t22.getNarrowLiteral());
                pc++; continue;
            }
            if (op == Opcode.MUL_INT || op == Opcode.XOR_INT
                    || op == Opcode.ADD_INT || op == Opcode.SUB_INT) {
                // dispatcher 的 scratch/state 运算：vA = vB op vC。执行不计入 trace。
                com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction23x t23 =
                        (com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction23x) insn;
                int a = t23.getRegisterA(), b = t23.getRegisterB(), c = t23.getRegisterC();
                int bv = regFile.getOrDefault(b, 0), cv = regFile.getOrDefault(c, 0);
                int result;
                if (op == Opcode.MUL_INT) result = bv * cv;
                else if (op == Opcode.XOR_INT) result = bv ^ cv;
                else if (op == Opcode.ADD_INT) result = bv + cv;
                else result = bv - cv;
                regFile.put(a, result);
                pc++; continue;
            }
            if (op == Opcode.MOVE) {
                com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction12x t12 =
                        (com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction12x) insn;
                regFile.put(t12.getRegisterA(), regFile.getOrDefault(t12.getRegisterB(), 0));
                pc++; continue;
            }
            if (op == Opcode.MOVE_FROM16) {
                com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22x t22 =
                        (com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22x) insn;
                regFile.put(t22.getRegisterA(), regFile.getOrDefault(t22.getRegisterB(), 0));
                pc++; continue;
            }
            if (op == Opcode.CONST_16 || op == Opcode.CONST) {
                int reg = ((com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction)
                        insn).getRegisterA();
                int lit = ((com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction)
                        insn).getNarrowLiteral();
                regFile.put(reg, lit);
                if (recording && reg >= regShift) {
                    trace.add("const v" + reg + " " + lit);
                    vval = (reg == workReg) ? lit : vval;
                }
                pc++; continue;
            }
            if (op == Opcode.IF_EQZ || op == Opcode.IF_NEZ) {
                int reg = ((Instruction21t) insn).getRegisterA();
                boolean gluePredicate = hasDispatcher && reg < regShift;
                if (recording && !gluePredicate) trace.add(op.name + " v" + reg);
                int rv = regFile.getOrDefault(reg, 0);
                boolean taken = op == Opcode.IF_EQZ ? rv == 0 : rv != 0;
                if (taken) { pc = branchTargetIndex(impl, pc); continue; }
                pc++; continue;
            }
            if (op == Opcode.CONST_4) {
                int reg = ((Instruction11n) insn).getRegisterA();
                int lit = ((Instruction11n) insn).getNarrowLiteral();
                regFile.put(reg, lit);
                if (recording && reg >= regShift) trace.add("const v" + reg + " " + lit);
                pc++; continue;
            }
            if (op == Opcode.RETURN_VOID) { if (recording) trace.add("return-void"); break; }
            if (recording) trace.add("?" + op);
            pc++;
        }
        return trace;
    }

    private final Map<Integer, Integer> regFile = new HashMap<>();

    /** 把 trace 里形如 "vN" 的寄存器号整体 +delta，用于抵消平坦化的寄存器平移。 */
    private static List<String> shiftRegsInTrace(List<String> trace, int delta) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("v(\\d+)");
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String s : trace) {
            java.util.regex.Matcher m = p.matcher(s);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                int reg = Integer.parseInt(m.group(1)) + delta;
                m.appendReplacement(sb, "v" + reg);
            }
            m.appendTail(sb);
            out.add(sb.toString());
        }
        return out;
    }

    private int packedSwitchTarget(MutableMethodImplementation impl, int switchPc, int key) {
        // 找到 payload：packed-switch 的 target label 指向 payload 指令；case key -> 第 key 个元素。
        com.android.tools.smali.dexlib2.builder.BuilderInstruction sw = impl.getInstructions().get(switchPc);
        com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction off =
                (com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction) sw;
        int payloadIdx = off.getTarget().getLocation().getIndex();
        com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload payload =
                (com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload)
                        impl.getInstructions().get(payloadIdx);
        List<? extends com.android.tools.smali.dexlib2.iface.instruction.SwitchElement> elems = payload.getSwitchElements();
        for (com.android.tools.smali.dexlib2.iface.instruction.SwitchElement e : elems) {
            if (e.getKey() == key) {
                // element offset 是相对 switch 指令的 code offset；用 dexlib2 的 builder target 更稳：
                // 这里回退用 code address 计算——但 builder payload 暴露的是 offset，故用地址映射。
                return codeAddressToIndex(impl, sw, e.getOffset());
            }
        }
        return impl.getInstructions().size(); // 越界 => 结束
    }

    private int codeAddressToIndex(MutableMethodImplementation impl,
                                   com.android.tools.smali.dexlib2.builder.BuilderInstruction switchInsn,
                                   int offsetFromSwitch) {
        int swAddr = switchInsn.getLocation().getCodeAddress();
        int targetAddr = swAddr + offsetFromSwitch;
        List<com.android.tools.smali.dexlib2.builder.BuilderInstruction> insns = impl.getInstructions();
        for (int i = 0; i < insns.size(); i++) {
            if (insns.get(i).getLocation().getCodeAddress() == targetAddr) return i;
        }
        return insns.size();
    }

    private int branchTargetIndex(MutableMethodImplementation impl,
                                  int pc) {
        com.android.tools.smali.dexlib2.builder.BuilderInstruction insn = impl.getInstructions().get(pc);
        com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction off =
                (com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction) insn;
        return off.getTarget().getLocation().getIndex();
    }

    private static boolean isGotoFamily(Opcode op) {
        return op == Opcode.GOTO || op == Opcode.GOTO_16 || op == Opcode.GOTO_32;
    }

    private static Map<Opcode, Integer> opcodeHistogram(MethodImplementation impl) {
        Map<Opcode, Integer> h = new HashMap<>();
        for (Instruction i : impl.getInstructions()) {
            h.merge(i.getOpcode(), 1, Integer::sum);
        }
        return h;
    }

    /** 测试只需要 implementation，用最小 stub 充当 Method。 */
    private com.android.tools.smali.dexlib2.iface.Method fakeMethod() {
        return fakeMethod("sample");
    }

    private com.android.tools.smali.dexlib2.iface.Method fakeMethod(String methodName) {
        return fakeMethod(methodName, "V");
    }

    private com.android.tools.smali.dexlib2.iface.Method fakeMethod(String methodName, String returnType) {
        return fakeMethod(methodName, returnType,
                com.android.tools.smali.dexlib2.AccessFlags.STATIC.getValue());
    }

    private com.android.tools.smali.dexlib2.iface.Method fakeMethod(
            String methodName, String returnType, int accessFlags) {
        return (com.android.tools.smali.dexlib2.iface.Method) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{com.android.tools.smali.dexlib2.iface.Method.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getDefiningClass": return "Lcom/example/Test;";
                        case "getName": return methodName;
                        // static 方法、无参 —— 供 MethodUtil.getParameterRegisterCount 使用（返回 0）。
                        case "getParameterTypes": return java.util.Collections.emptyList();
                        case "getParameters": return java.util.Collections.emptyList();
                        case "getAccessFlags": return accessFlags;
                        case "getReturnType": return returnType;
                        case "toString": return "Lcom/example/Test;->" + methodName;
                        default: return null;
                    }
                });
    }
}
