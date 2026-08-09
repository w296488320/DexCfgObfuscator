package com.zhenxi.hunter.obfuscator;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * CfgFlattener —— 控制流混淆核心（基本块重排 / basic-block reordering）。
 *
 * 为什么用 dexlib2 的 {@link MethodImplementationBuilder}：
 *   它用**具名标签**（{@code getLabel/addLabel}）表示跳转目标，允许我们把基本块按任意
 *   （被打乱的）物理顺序发射出去，跳转目标靠 Label 前向/后向引用自动解析；发射完成后
 *   dexlib2 自动重算所有分支偏移，并在偏移超出 8/16 位时把 GOTO 自动升格为
 *   GOTO_16 / GOTO_32（见 fixInstructions）。BlackObfuscator 基于 dex2jar 的
 *   DEX->IR->DEX 往返 + **手工**重排/算偏移，才会把偏移/寄存器算溢出
 *   （"Unsigned short value out of range: 65540"）导致真机 VerifyError。
 *
 * 为什么**不能**用 MutableMethodImplementation.swapInstructions 原地重排：
 *   swapInstructions 只交换两个 MethodLocation 的 instruction 字段，**Label 仍绑定在
 *   原 location 上、不随指令移动**。因此任何“相邻交换”都会静默破坏所有分支目标。
 *   正确做法只能是：以块为单位重新发射，并用新的具名 Label 重建每一条分支。
 *
 * 混淆原理（零新增寄存器，语义完全不变）：
 *   1. 把方法体按基本块切分（分支/返回/抛出的下一条、以及跳转目标处为块首 leader）。
 *   2. 把所有块**打乱物理顺序**重新发射；在方法开头发射一条 `goto 原入口块`，
 *      保证执行仍从原入口开始。
 *   3. 对“会顺序落入下一块”的块尾（普通落空 or 条件分支的 else 边）补一条
 *      `goto 原后继块`，使执行序完全由 goto/条件跳转串联，与原方法逐指令一致；
 *      但物理布局被彻底打散，jadx/JEB 做控制流重建时得到大量交叉跳转、无法线性化。
 *
 * 安全约束（任一不满足 => 返回 null，该方法保持原样，绝不“尽力混淆”）：
 *   1. skipMethodsWithTryCatch：含 try/catch 的方法跳过（重排会破坏 try 区间）。
 *   2. 含 packed/sparse-switch 或 array-data payload 的方法跳过（payload 有位置/对齐约束）。
 *   3. 方法过小（切不出 >=3 块）或过大（>maxInstructions）跳过。
 *   4. 任何分支目标无法解析、或落空跑出方法末尾时整段放弃。
 */
final class CfgFlattener {

    private final ObfuscatorConfig config;
    private final ObfuscatorLogger logger;
    private final ObfuscatorStats stats;

    CfgFlattener(ObfuscatorConfig config, ObfuscatorLogger logger, ObfuscatorStats stats) {
        this.config = config;
        this.logger = logger;
        this.stats = stats;
    }

    MethodImplementation flatten(Method method, MethodImplementation impl) {
        if (config.skipMethodsWithTryCatch && hasTryBlocks(impl)) {
            stats.methodsSkippedTryCatch++;
            return null;
        }
        // payload / switch / 大小 预检：直接读原始 Instruction 的 opcode，无需构造 mutable。
        int insnCount = 0;
        for (Instruction insn : impl.getInstructions()) {
            insnCount++;
            if (isPayloadOrSwitch(insn.getOpcode())) {
                stats.methodsSkippedUnsupported++;
                return null;
            }
        }
        if (insnCount < 4) {
            stats.methodsSkippedTooSmall++;
            return null;
        }
        if (insnCount > config.maxInstructions) {
            stats.methodsSkippedTooLarge++;
            return null;
        }

        try {
            return reorderBasicBlocks(impl);
        } catch (Throwable t) {
            logger.warn("flatten failed on " + method.getDefiningClass() + "->" + method.getName()
                    + " : " + t + " (keep original)");
            stats.methodsSkippedUnsupported++;
            return null;
        }
    }

    /**
     * 以块为单位、按打乱顺序重新发射整个方法体；用具名 Label 重建所有分支。
     */
    private MethodImplementation reorderBasicBlocks(MethodImplementation impl) {
        MutableMethodImplementation src = new MutableMethodImplementation(impl);
        List<BuilderInstruction> insns = src.getInstructions();
        int n = insns.size();

        List<int[]> blocks = computeBlocks(insns);
        if (blocks == null) {
            stats.methodsSkippedUnsupported++;
            return null;
        }
        int bc = blocks.size();
        if (bc < 3) {
            stats.methodsSkippedTooSmall++;
            return null;
        }

        // 生成块的乱序排列（固定种子 => 可复现构建）。
        Integer[] order = new Integer[bc];
        for (int i = 0; i < bc; i++) order[i] = i;
        Random rnd = new Random(stableSeed(impl, n, bc));
        for (int i = bc - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            Integer t = order[i]; order[i] = order[j]; order[j] = t;
        }

        MethodImplementationBuilder out = new MethodImplementationBuilder(src.getRegisterCount());

        // 入口：跳到“原入口块”（原始 index 0 处）所在的新位置。
        out.addInstruction(new BuilderInstruction10t(Opcode.GOTO, out.getLabel(blockLabel(0))));

        for (int oi = 0; oi < bc; oi++) {
            int[] blk = blocks.get(order[oi]);
            int start = blk[0];
            int end = blk[1];

            // 该块首指令处放置具名标签（addLabel 绑定到“下一条将被发射的指令”）。
            out.addLabel(blockLabel(start));
            for (int i = start; i < end; i++) {
                BuilderInstruction insn = insns.get(i);
                BuilderInstruction rebuilt = rebuildBranch(insn, out);
                out.addInstruction(rebuilt != null ? rebuilt : insn);
            }

            // 若块尾会“顺序落入下一块”（普通落空 或 条件分支 else 边），补显式 goto。
            Opcode lastOp = insns.get(end - 1).getOpcode();
            if (fallsThrough(lastOp) || isConditional(lastOp)) {
                if (end >= n) {
                    // 落空跑出方法末尾 —— 非法输入，放弃。
                    stats.methodsSkippedUnsupported++;
                    return null;
                }
                out.addInstruction(new BuilderInstruction10t(Opcode.GOTO, out.getLabel(blockLabel(end))));
            }
        }

        return out.getMethodImplementation();
    }

    /**
     * 若指令是分支（goto / if-*），用**新 impl 上的具名 Label** 重建它；否则返回 null（表示原样复用）。
     * 目标 Label 名 = 目标指令在原始序中的 index（该 index 必为某基本块的 leader）。
     */
    private BuilderInstruction rebuildBranch(BuilderInstruction insn, MethodImplementationBuilder out) {
        if (!(insn instanceof BuilderOffsetInstruction)) {
            return null;
        }
        Integer tgt = builderBranchTargetIndex(insn);
        if (tgt == null) {
            throw new IllegalStateException("unresolved branch target");
        }
        Label lbl = out.getLabel(blockLabel(tgt));
        Opcode op = insn.getOpcode();
        if (isGoto(op)) {
            // 统一发射 GOTO(10t)，dexlib2 会按偏移自动升格 GOTO_16/GOTO_32。
            return new BuilderInstruction10t(Opcode.GOTO, lbl);
        }
        if (insn instanceof BuilderInstruction21t) {
            return new BuilderInstruction21t(op, ((BuilderInstruction21t) insn).getRegisterA(), lbl);
        }
        if (insn instanceof BuilderInstruction22t) {
            BuilderInstruction22t t = (BuilderInstruction22t) insn;
            return new BuilderInstruction22t(op, t.getRegisterA(), t.getRegisterB(), lbl);
        }
        // packed/sparse-switch(31t) 已在 flatten 预检排除；出现其它 offset 指令则放弃整段。
        throw new IllegalStateException("unsupported offset instruction: " + op);
    }

    /** 计算基本块 [start,end) 列表；任一分支目标不可解析返回 null。 */
    private List<int[]> computeBlocks(List<BuilderInstruction> insns) {
        int n = insns.size();
        if (n == 0) return new ArrayList<>();
        boolean[] leader = new boolean[n];
        leader[0] = true;
        for (int i = 0; i < n; i++) {
            BuilderInstruction insn = insns.get(i);
            Opcode op = insn.getOpcode();
            if (isBranch(op)) {
                if (i + 1 < n) leader[i + 1] = true;
                Integer tgt = builderBranchTargetIndex(insn);
                if (tgt == null || tgt < 0 || tgt >= n) return null;
                leader[tgt] = true;
            } else if (isReturn(op) || op == Opcode.THROW) {
                if (i + 1 < n) leader[i + 1] = true;
            }
        }
        List<int[]> blocks = new ArrayList<>();
        int s = 0;
        for (int i = 1; i <= n; i++) {
            if (i == n || leader[i]) { blocks.add(new int[]{s, i}); s = i; }
        }
        return blocks;
    }

    private static String blockLabel(int originalIndex) {
        return "B" + originalIndex;
    }

    // ---- opcode 语义 ----

    private static boolean isBranch(Opcode op) {
        return isGoto(op) || isConditional(op);
    }

    private static boolean isGoto(Opcode op) {
        return op == Opcode.GOTO || op == Opcode.GOTO_16 || op == Opcode.GOTO_32;
    }

    private static boolean isConditional(Opcode op) {
        switch (op) {
            case IF_EQ: case IF_NE: case IF_LT: case IF_GE: case IF_GT: case IF_LE:
            case IF_EQZ: case IF_NEZ: case IF_LTZ: case IF_GEZ: case IF_GTZ: case IF_LEZ:
                return true;
            default:
                return false;
        }
    }

    private static boolean fallsThrough(Opcode op) {
        if (isGoto(op)) return false;
        if (isReturn(op) || op == Opcode.THROW) return false;
        return true;
    }

    private static boolean isReturn(Opcode op) {
        switch (op) {
            case RETURN_VOID: case RETURN: case RETURN_WIDE: case RETURN_OBJECT:
            case RETURN_VOID_NO_BARRIER:
                return true;
            default:
                return false;
        }
    }

    private static boolean isPayloadOrSwitch(Opcode op) {
        switch (op) {
            case PACKED_SWITCH: case SPARSE_SWITCH:
            case PACKED_SWITCH_PAYLOAD: case SPARSE_SWITCH_PAYLOAD:
            case ARRAY_PAYLOAD: case FILL_ARRAY_DATA:
                return true;
            default:
                return false;
        }
    }

    /** 取 builder 分支指令目标的索引（无反射）。非 offset 指令返回 null。 */
    private static Integer builderBranchTargetIndex(BuilderInstruction insn) {
        if (insn instanceof BuilderOffsetInstruction) {
            Label target = ((BuilderOffsetInstruction) insn).getTarget();
            if (target == null) return null;
            if (target.getLocation() == null) return null;
            return target.getLocation().getIndex();
        }
        return null;
    }

    private static boolean hasTryBlocks(MethodImplementation impl) {
        List<? extends TryBlock<? extends ExceptionHandler>> tries = impl.getTryBlocks();
        return tries != null && !tries.isEmpty();
    }

    private static long stableSeed(MethodImplementation impl, int n, int blocks) {
        long h = 1125899906842597L;
        h = 31 * h + n;
        h = 31 * h + blocks;
        h = 31 * h + impl.getRegisterCount();
        return h;
    }
}
