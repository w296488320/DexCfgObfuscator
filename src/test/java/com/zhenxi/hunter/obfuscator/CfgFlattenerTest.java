package com.zhenxi.hunter.obfuscator;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21t;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction11n;

import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
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
    public void reordersAndPreservesInstructions() {
        MutableMethodImplementation src = buildSample();
        Map<Opcode, Integer> before = opcodeHistogram(src);

        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation out = newFlattener(stats).flatten(fakeMethod(), src);

        assertNotNull("expected obfuscation to succeed on multi-block method", out);

        // 混淆后可被 dexlib2 重新构造（结构合法、所有 Label 可解析）。
        MutableMethodImplementation reparsed = new MutableMethodImplementation(out);
        assertTrue("reparsed must contain at least the original instructions",
                reparsed.getInstructions().size() >= before.values().stream().mapToInt(Integer::intValue).sum());

        // 原始 opcode 直方图被完整保留（新增只能是 goto 家族）。
        Map<Opcode, Integer> after = opcodeHistogram(out);
        for (Map.Entry<Opcode, Integer> e : before.entrySet()) {
            if (isGotoFamily(e.getKey())) continue;
            int a = after.getOrDefault(e.getKey(), 0);
            assertTrue("original opcode lost: " + e.getKey() + " before=" + e.getValue() + " after=" + a,
                    a >= e.getValue());
        }
        int gotoAfter = 0;
        for (Map.Entry<Opcode, Integer> e : after.entrySet()) {
            if (isGotoFamily(e.getKey())) gotoAfter += e.getValue();
        }
        assertTrue("expected added GOTOs for block chaining", gotoAfter >= 1);

        // 语义等价：模拟执行，对比“非 goto 指令”的访问序列。
        List<String> origTrace = simulate(src);
        List<String> obfTrace = simulate(new MutableMethodImplementation(out));
        assertEquals("execution trace (excluding gotos) must be identical", origTrace, obfTrace);
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

    /**
     * 极简 DEX 解释器：只处理本测试用到的指令族（const/4、if-eqz、goto、return-void）。
     * 返回“执行过的非 goto 指令”的规范化描述序列，用于判定语义等价。
     * v0 初值取 0，使 if-eqz 命中跳转，覆盖“条件为真”的路径。
     */
    private List<String> simulate(MutableMethodImplementation impl) {
        List<com.android.tools.smali.dexlib2.builder.BuilderInstruction> insns = impl.getInstructions();
        java.util.ArrayList<String> trace = new java.util.ArrayList<>();
        int v0 = 0;
        int pc = 0;
        int steps = 0;
        while (pc >= 0 && pc < insns.size() && steps++ < 1000) {
            Instruction insn = insns.get(pc);
            Opcode op = insn.getOpcode();
            if (isGotoFamily(op)) {
                pc = branchTargetIndex(impl, pc);
                continue;
            }
            if (op == Opcode.IF_EQZ) {
                trace.add("if-eqz v" + ((Instruction21t) insn).getRegisterA());
                if (v0 == 0) { pc = branchTargetIndex(impl, pc); continue; }
                pc++;
                continue;
            }
            if (op == Opcode.CONST_4) {
                trace.add("const/4 v" + ((Instruction11n) insn).getRegisterA()
                        + " " + ((Instruction11n) insn).getNarrowLiteral());
                v0 = ((Instruction11n) insn).getNarrowLiteral();
                pc++;
                continue;
            }
            if (op == Opcode.RETURN_VOID) {
                trace.add("return-void");
                break;
            }
            trace.add("?" + op);
            pc++;
        }
        return trace;
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
        return (com.android.tools.smali.dexlib2.iface.Method) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{com.android.tools.smali.dexlib2.iface.Method.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getDefiningClass": return "Lcom/zhenxi/Test;";
                        case "getName": return "sample";
                        case "toString": return "Lcom/zhenxi/Test;->sample";
                        default: return null;
                    }
                });
    }
}
