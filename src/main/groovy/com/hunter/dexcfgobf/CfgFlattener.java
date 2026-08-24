package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.SwitchLabelElement;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderArrayPayload;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction23x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31i;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderPackedSwitchPayload;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderSparseSwitchPayload;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderSwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * CfgFlattener —— 控制流混淆入口（控制流平坦化 + 基本块重排安全回退）。
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
 * 基本块重排回退原理（零新增寄存器，语义完全不变）：
 *   1. 把方法体按基本块切分（分支/返回/抛出的下一条、以及跳转目标处为块首 leader）。
 *   2. 把所有块**打乱物理顺序**重新发射；在方法开头发射一条 `goto 原入口块`，
 *      保证执行仍从原入口开始。
 *   3. 对“会顺序落入下一块”的块尾（普通落空 or 条件分支的 else 边）补一条
 *      `goto 原后继块`，使执行序完全由 goto/条件跳转串联，与原方法逐指令一致；
 *      但物理布局被彻底打散，jadx/JEB 做控制流重建时得到大量交叉跳转、无法线性化。
 *
 * 安全约束（任一不满足 => 返回 null，该方法保持原样，绝不“尽力混淆”）：
 *   1. skipMethodsWithTryCatch=true：含 try/catch 的方法按配置跳过；false 时重建 try 区间。
 *   2. 含 packed/sparse-switch 或 array-data payload 的方法跳过（payload 有位置/对齐约束）。
 *   3. 方法过小（切不出 >=3 块）或过大（>maxInstructions）跳过。
 *   4. 任何分支目标无法解析、或落空跑出方法末尾时整段放弃。
 */
final class CfgFlattener {

    private final ObfuscatorConfig config;
    private final ObfuscatorLogger logger;
    private final ObfuscatorStats stats;
    private TransformationOutcome lastOutcome;
    private TransformationOutcome.Reason reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
    private int paddedSwitches;
    private int switchCasesBefore;
    private int switchCasesAfter;
    private int fakeSwitchCases;
    private int symbolSwitchCases;
    private int reorderScratchAdded;

    CfgFlattener(ObfuscatorConfig config, ObfuscatorLogger logger, ObfuscatorStats stats) {
        this.config = config;
        this.logger = logger;
        this.stats = stats;
    }

    MethodImplementation flatten(Method method, MethodImplementation impl) {
        return flatten(method, impl, false, 0);
    }

    MethodImplementation flatten(Method method, MethodImplementation impl,
                                 boolean registerTypesSeparated, int addedRegisters) {
        lastOutcome = null;
        resetSwitchPaddingStats();
        // 基本块重排会写入一个零寄存器、不可达的显式标记。Gradle 在 producer task
        // up-to-date 时可能再次执行本 task；没有这个判断会对同一份 dex 反复重排。
        if (ObfuscationMarker.hasV1(impl)) {
            return finish(null, TransformationOutcome.skipped(
                    TransformationOutcome.Reason.ALREADY_OBFUSCATED));
        }

        // switch / 大小 预检：直接读原始 Instruction 的 opcode。
        // 含 packed/sparse-switch 的方法跳过（switch payload 有位置/对齐/多目标约束，暂不支持）。
        // 注意：array-data / fill-array-data **不再**在此跳过——内置字符串加密会给几乎所有
        // 方法带上 fill-array-data，若此处跳过将导致大量方法完全不混淆。flatten/reorder 现已支持
        // 把 array-data payload 重定位到方法尾部（dexlib2 自动对齐）。
        int insnCount = 0;
        for (Instruction insn : impl.getInstructions()) {
            insnCount++;
            if (!config.enablePayloadRelocation && isSwitch(insn.getOpcode())) {
                return finish(null, TransformationOutcome.skipped(
                        TransformationOutcome.Reason.SWITCH_UNSUPPORTED));
            }
        }
        if (insnCount < 4) {
            return finish(null, TransformationOutcome.skipped(
                    TransformationOutcome.Reason.TOO_SMALL));
        }
        if (insnCount > config.maxInstructions) {
            return finish(null, TransformationOutcome.skipped(
                    TransformationOutcome.Reason.TOO_LARGE));
        }

        try {
            // ---- 混合分派 ----
            // A) 含 try/catch：平坦化会破坏 move-exception 必为 handler 首指令的约束，
            //    故走“携带 try 表的基本块重排”（reorder 不在块首插 glue，move-exception 仍是块首）。
            boolean hasTry = hasTryBlocks(impl);
            if (hasTry && config.skipMethodsWithTryCatch) {
                return finish(null, TransformationOutcome.skipped(
                        TransformationOutcome.Reason.TRY_CATCH_DISABLED));
            }
            int paramRegs = com.android.tools.smali.dexlib2.util.MethodUtil.getParameterRegisterCount(method);
            MethodImplementation out = null;
            // B) 只有“静态 + 纯整数 + 无异常表”的方法才允许控制流平坦化。
            //    D8/R8 会让同一寄存器在不相交生命周期里承载 String、byte[]、对象等不同
            //    verifier 类型；dispatcher 增加的汇合边会把这些生命周期错误地连在一起，
            //    即使原 DEX 完全合法也会在 ART 启动时 VerifyError。因此这里必须使用白名单，
            //    其它方法统一走不增加 CFG 边的基本块重排。
            boolean flattenSafe = registerTypesSeparated || isFlattenSafe(method, impl);
            boolean flattenFailed = false;
            if (flattenSafe) {
                try {
                    long methodSeed = stableSeed(method, impl, insnCount, insnCount);
                    ControlFlowFlattener strong = new ControlFlowFlattener(config, stats);
                    out = strong.flatten(method, impl, methodSeed, paramRegs);
                    if (out != null) {
                        PostTransformBudget.verify(impl, out, config);
                        String template = ControlFlowFlattener.templateName(methodSeed, config);
                        return finish(out, new TransformationOutcome(
                                TransformationOutcome.Mode.FLATTENED,
                                registerTypesSeparated
                                        ? TransformationOutcome.Reason.VERIFIER_SEPARATED
                                        : TransformationOutcome.Reason.FLATTEN_SAFE,
                                template, registerTypesSeparated,
                                addedRegisters + ControlFlowFlattener.ADDED_REGISTERS,
                                0, 0, 0, 0, 0,
                                strong.getDispatcherRegions(), strong.getReachableAliasCases(), 2));
                    }
                } catch (Throwable ft) {
                    logger.warn("flatten fallback->reorder on " + method.getDefiningClass()
                            + "->" + method.getName() + " : " + ft);
                    out = null;
                    flattenFailed = true;
                }
            }
            // C) 回退：基本块重排（支持 try/catch；真机 dex2oat 验证稳定）。
            if (out == null) {
                reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
                // 原始 switch 的增强需要一个完全独立的 int/char scratch。先整体平移寄存器腾出 v0；
                // 任一 nibble/range 格式无法安全平移时，自动回退到零新增寄存器的原重排路径。
                if (config.enablePayloadRelocation && containsSwitchInstruction(impl)
                        && impl.getRegisterCount() + 1 <= config.maxRegisters) {
                    try {
                        RegisterShifter.Result shifted = RegisterShifter.shift(
                                new MutableMethodImplementation(impl), 1);
                        MethodImplementation shiftedImpl = shifted.builder.getMethodImplementation();
                        out = reorderBasicBlocks(method, shiftedImpl, 0);
                        if (out != null && paddedSwitches > 0) {
                            PostTransformBudget.verify(impl, out, config);
                            reorderScratchAdded = 1;
                        } else {
                            out = null;
                            resetSwitchPaddingStats();
                        }
                    } catch (Throwable switchPaddingFailure) {
                        logger.warn("switch padding fallback->reorder on " + method.getDefiningClass()
                                + "->" + method.getName() + " : " + switchPaddingFailure);
                        out = null;
                        resetSwitchPaddingStats();
                    }
                }
                if (out == null) {
                    reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
                    out = reorderBasicBlocks(method, impl, -1);
                    if (out != null) PostTransformBudget.verify(impl, out, config);
                }
            }
            if (out != null) {
                TransformationOutcome.Reason reason = hasTry
                        ? TransformationOutcome.Reason.TRY_CATCH_REORDER
                        : (flattenFailed ? TransformationOutcome.Reason.FLATTEN_FALLBACK_REORDER
                        : TransformationOutcome.Reason.VERIFIER_RISK_REORDER);
                return finish(out, new TransformationOutcome(
                        TransformationOutcome.Mode.REORDERED, reason,
                        paddedSwitches > 0 ? "cfg-reorder-dual-switch" : "cfg-reorder",
                        registerTypesSeparated, addedRegisters + reorderScratchAdded,
                        paddedSwitches, switchCasesBefore, switchCasesAfter,
                        fakeSwitchCases, symbolSwitchCases));
            }
            return finish(null, TransformationOutcome.skipped(reorderFailure));
        } catch (Throwable t) {
            logger.warn("obfuscate failed on " + method.getDefiningClass() + "->" + method.getName()
                    + " : " + t + " (keep original)");
            return finish(null, TransformationOutcome.skipped(
                    TransformationOutcome.Reason.UNSUPPORTED));
        }
    }

    TransformationOutcome getLastOutcome() {
        return lastOutcome;
    }

    private MethodImplementation finish(MethodImplementation implementation,
                                        TransformationOutcome outcome) {
        lastOutcome = outcome;
        stats.recordOutcome(outcome);
        return implementation;
    }

    /**
     * ART verifier 安全白名单。
     *
     * dispatcher 会给每个 case 块增加一条来自同一入口的普通控制流边。只要方法含对象、数组、
     * float/wide、invoke、字段访问或异常边，R8 的寄存器生命周期复用就可能在新汇合点产生类型
     * 冲突。准确修复需要完整 SSA + verifier 类型分析；在没有这层证明之前只平坦化静态纯整数
     * 方法。误判的代价只是少做强混淆，绝不能是让 App 无法启动。
     */
    private boolean isFlattenSafe(Method method, MethodImplementation impl) {
        if ((method.getAccessFlags() & com.android.tools.smali.dexlib2.AccessFlags.STATIC.getValue()) == 0) {
            return false;
        }
        // ART 并不把 Z/B/S/C 与普通 I 完全等价：return、aget/aput 等位置会保留窄类型。
        // dispatcher 的统一入口预置为 const 0，若把窄整数也纳入“纯 int”会在 return 处得到
        // Integer but expected Boolean/Byte。未做窄类型 SSA 证明前仅白名单 I/V。
        if (hasTryBlocks(impl) || !isPlainIntOrVoid(method.getReturnType())) {
            return false;
        }
        for (CharSequence type : method.getParameterTypes()) {
            if (!"I".equals(type == null ? null : type.toString())) return false;
        }
        for (Instruction insn : impl.getInstructions()) {
            if (!isPureIntOpcode(insn.getOpcode())) return false;
        }
        return true;
    }

    private static boolean isPlainIntOrVoid(String type) {
        return "V".equals(type) || "I".equals(type);
    }

    /** 只允许 verifier 类型始终属于 int-category 的指令。 */
    private static boolean isPureIntOpcode(Opcode op) {
        switch (op) {
            case NOP:
            case MOVE: case MOVE_FROM16: case MOVE_16:
            case RETURN_VOID: case RETURN_VOID_NO_BARRIER: case RETURN:
            case CONST_4: case CONST_16: case CONST: case CONST_HIGH16:
            case GOTO: case GOTO_16: case GOTO_32:
            case IF_EQ: case IF_NE: case IF_LT: case IF_GE: case IF_GT: case IF_LE:
            case IF_EQZ: case IF_NEZ: case IF_LTZ: case IF_GEZ: case IF_GTZ: case IF_LEZ:
            case NEG_INT: case NOT_INT:
            case ADD_INT: case SUB_INT: case MUL_INT: case DIV_INT: case REM_INT:
            case AND_INT: case OR_INT: case XOR_INT: case SHL_INT: case SHR_INT: case USHR_INT:
            case ADD_INT_2ADDR: case SUB_INT_2ADDR: case MUL_INT_2ADDR:
            case DIV_INT_2ADDR: case REM_INT_2ADDR: case AND_INT_2ADDR:
            case OR_INT_2ADDR: case XOR_INT_2ADDR: case SHL_INT_2ADDR:
            case SHR_INT_2ADDR: case USHR_INT_2ADDR:
            case ADD_INT_LIT16: case RSUB_INT: case MUL_INT_LIT16:
            case DIV_INT_LIT16: case REM_INT_LIT16: case AND_INT_LIT16:
            case OR_INT_LIT16: case XOR_INT_LIT16:
            case ADD_INT_LIT8: case RSUB_INT_LIT8: case MUL_INT_LIT8:
            case DIV_INT_LIT8: case REM_INT_LIT8: case AND_INT_LIT8:
            case OR_INT_LIT8: case XOR_INT_LIT8: case SHL_INT_LIT8:
            case SHR_INT_LIT8: case USHR_INT_LIT8:
                return true;
            default:
                return false;
        }
    }

    /**
     * 以块为单位、按打乱顺序重新发射整个方法体；用具名 Label 重建所有分支。
     */
    private MethodImplementation reorderBasicBlocks(Method method, MethodImplementation impl,
                                                    int switchScratchReg) {
        MutableMethodImplementation src = new MutableMethodImplementation(impl);
        List<BuilderInstruction> insns = src.getInstructions();
        int n = insns.size();

        // D8/R8 把 switch/array payload 放在可执行区尾部，并可能在其前插入对齐 NOP。
        // 重排只接受这种规范布局：抽出尾部数据区，块内 31t 指令重绑新 Label，最后重发 payload。
        int execN = n;
        for (int i = 0; i < n; i++) {
            if (isPayload(insns.get(i).getOpcode())) {
                execN = i;
                break;
            }
        }
        while (execN > 0 && insns.get(execN - 1).getOpcode() == Opcode.NOP) execN--;
        List<Integer> payloadIndices = new ArrayList<>();
        for (int i = execN; i < n; i++) {
            Opcode op = insns.get(i).getOpcode();
            if (isPayload(op)) payloadIndices.add(i);
            else if (op != Opcode.NOP) {
                reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
                return null;
            }
        }

        // 收集 try 边界 + handler 作为额外 leader，保证它们落在块首。
        List<? extends TryBlock<? extends ExceptionHandler>> tries = src.getTryBlocks();
        boolean[] extraLeader = new boolean[n + 1];
        List<int[]> tryRanges = new ArrayList<>();      // {startIdx, endIdx, handlerIdx, typeSlot}
        List<TypeReference> tryTypes = new ArrayList<>();
        if (tries != null) {
            for (TryBlock<? extends ExceptionHandler> tb : tries) {
                int sIdx = ((com.android.tools.smali.dexlib2.builder.BuilderTryBlock) tb).start.getLocation().getIndex();
                int eIdx = ((com.android.tools.smali.dexlib2.builder.BuilderTryBlock) tb).end.getLocation().getIndex();
                if (sIdx < 0 || eIdx > execN || sIdx >= eIdx) {
                    reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
                    return null;
                }
                if (sIdx <= n) extraLeader[sIdx] = true;
                if (eIdx <= n) extraLeader[eIdx] = true;
                for (ExceptionHandler h : tb.getExceptionHandlers()) {
                    int hIdx = ((com.android.tools.smali.dexlib2.builder.BuilderExceptionHandler)
                            h).getHandler().getLocation().getIndex();
                    if (hIdx >= 0 && hIdx < execN) extraLeader[hIdx] = true;
                    tryRanges.add(new int[]{sIdx, eIdx, hIdx, tryTypes.size()});
                    tryTypes.add(h.getExceptionTypeReference());
                }
            }
        }

        List<int[]> blocks = computeBlocks(insns, extraLeader, execN);
        if (blocks == null) {
            reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
            return null;
        }
        int bc = blocks.size();
        if (bc < 3) {
            reorderFailure = TransformationOutcome.Reason.TOO_SMALL;
            return null;
        }

        // 原指令索引 -> 块号。
        int[] blockOfIndex = new int[execN + 1];
        for (int b = 0; b < bc; b++)
            for (int i = blocks.get(b)[0]; i < blocks.get(b)[1]; i++) blockOfIndex[i] = b;
        blockOfIndex[execN] = bc;

        // 生成块的乱序排列（固定种子 => 可复现构建）。
        Integer[] order = new Integer[bc];
        for (int i = 0; i < bc; i++) order[i] = i;
        long reorderSeed = stableSeed(method, impl, n, bc);
        Random rnd = new Random(reorderSeed);
        for (int i = bc - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            Integer t = order[i]; order[i] = order[j]; order[j] = t;
        }

        Map<Integer, SwitchPaddingPlan> switchPlans = switchScratchReg >= 0
                ? buildSwitchPaddingPlans(insns, execN, reorderSeed)
                : Collections.emptyMap();
        if (switchScratchReg >= 0 && switchPlans.isEmpty()) {
            return null;
        }
        Map<Integer, SwitchPaddingPlan> plansByPayload = new LinkedHashMap<>();
        for (SwitchPaddingPlan plan : switchPlans.values()) {
            plansByPayload.put(plan.payloadIndex, plan);
        }

        MethodImplementationBuilder out = new MethodImplementationBuilder(src.getRegisterCount());

        // 入口前写入共享 V1 幂等标记；不读写寄存器、不进入 try 区间，也不改变可达语义。
        Label originalEntry = out.getLabel(blockLabel(0));
        ObfuscationMarker.emitV1(out, originalEntry);

        for (int oi = 0; oi < bc; oi++) {
            int[] blk = blocks.get(order[oi]);
            int start = blk[0];
            int end = blk[1];

            // 该块首指令处放置具名标签。move-exception 作为 handler 块首指令，
            // 因为我们不在块首插任何 glue，故其“必为 handler 首指令”的约束天然满足。
            out.addLabel(blockLabel(start));
            for (int i = start; i < end; i++) {
                BuilderInstruction insn = insns.get(i);
                SwitchPaddingPlan switchPlan = switchPlans.get(i);
                if (switchPlan != null) {
                    emitPaddedSwitch(out, switchPlan, switchScratchReg);
                } else {
                    BuilderInstruction rebuilt = rebuildBranch(insn, out);
                    out.addInstruction(rebuilt != null ? rebuilt : insn);
                }
            }
            // 块真实指令结束标签（try 区间上界用）。
            out.addLabel(blockEndLabel(start));

            // 若块尾会“顺序落入下一块”，补显式 goto（在 blockEnd 之后，不在 try 覆盖内）。
            Opcode lastOp = insns.get(end - 1).getOpcode();
            boolean paddedSwitchTail = switchPlans.containsKey(end - 1);
            if (!paddedSwitchTail && (fallsThrough(lastOp) || isConditional(lastOp))) {
                if (end >= execN) {
                    reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
                    return null;
                }
                out.addInstruction(new BuilderInstruction10t(Opcode.GOTO, out.getLabel(blockLabel(end))));
            }
        }

        // 第一层的随机 32 位 case 先经形状相同的 bridge 映射到第二层可见字符 case。
        // 第二层真实/伪 case 再经 trampoline 分别跳原 target/default。两层都只改 scratch。
        for (SwitchPaddingPlan plan : switchPlans.values()) {
            for (int ri = 0; ri < plan.realCases.size(); ri++) {
                SwitchCasePlan real = plan.realCases.get(ri);
                emitSwitchSymbolBridge(out, switchOuterRealLabel(plan.switchIndex, ri),
                        switchOuterAltLabel(plan.switchIndex, ri, false),
                        switchScratchReg, real.symbolKey, reorderSeed,
                        plan.switchIndex * 193 + ri,
                        out.getLabel(switchCharDispatchLabel(plan.switchIndex)));
            }
            for (int fi = 0; fi < plan.fakeCases.size(); fi++) {
                SwitchFakeCasePlan fake = plan.fakeCases.get(fi);
                emitSwitchSymbolBridge(out, switchOuterFakeLabel(plan.switchIndex, fi),
                        switchOuterAltLabel(plan.switchIndex, fi, true),
                        switchScratchReg, fake.symbolKey,
                        reorderSeed ^ 0x94D049BB133111EBL,
                        plan.switchIndex * 389 + fi,
                        out.getLabel(switchCharDispatchLabel(plan.switchIndex)));
            }

            out.addLabel(switchCharDispatchLabel(plan.switchIndex));
            out.addInstruction(new BuilderInstruction12x(
                    Opcode.INT_TO_CHAR, switchScratchReg, switchScratchReg));
            out.addInstruction(new BuilderInstruction31t(
                    Opcode.SPARSE_SWITCH, switchScratchReg,
                    out.getLabel(switchCharPayloadLabel(plan.switchIndex))));
            out.addInstruction(new BuilderInstruction10t(
                    Opcode.GOTO, out.getLabel(blockLabel(plan.defaultIndex))));

            for (int ri = 0; ri < plan.realCases.size(); ri++) {
                SwitchCasePlan real = plan.realCases.get(ri);
                emitSwitchTrampoline(out, switchRealLabel(plan.switchIndex, ri),
                        switchAltLabel(plan.switchIndex, ri, false),
                        switchScratchReg, reorderSeed, plan.switchIndex * 257 + ri,
                        out.getLabel(blockLabel(real.targetIndex)));
            }
            for (int fi = 0; fi < plan.fakeCases.size(); fi++) {
                emitSwitchTrampoline(out, switchFakeLabel(plan.switchIndex, fi),
                        switchAltLabel(plan.switchIndex, fi, true),
                        switchScratchReg, reorderSeed ^ 0xD1B54A32D192ED03L,
                        plan.switchIndex * 521 + fi,
                        out.getLabel(blockLabel(plan.defaultIndex)));
            }
        }

        // 重发抽出的数据区。所有 case 目标仍指向原 CFG 的块首，31t 目标则指向这里的新 payload。
        for (int payloadIndex : payloadIndices) {
            BuilderInstruction payload = insns.get(payloadIndex);
            out.addLabel(payloadLabel(payloadIndex));
            SwitchPaddingPlan padded = plansByPayload.get(payloadIndex);
            if (padded != null) {
                List<SwitchLabelElement> elements = new ArrayList<>(
                        padded.realCases.size() + padded.fakeCases.size());
                for (int ci = 0; ci < padded.realCases.size(); ci++) {
                    elements.add(new SwitchLabelElement(padded.realCases.get(ci).encodedKey,
                            out.getLabel(switchOuterRealLabel(padded.switchIndex, ci))));
                }
                for (int fi = 0; fi < padded.fakeCases.size(); fi++) {
                    elements.add(new SwitchLabelElement(padded.fakeCases.get(fi).encodedKey,
                            out.getLabel(switchOuterFakeLabel(padded.switchIndex, fi))));
                }
                elements.sort((a, b) -> Integer.compare(a.key, b.key));
                out.addInstruction(new BuilderSparseSwitchPayload(elements));
            } else if (payload instanceof BuilderArrayPayload) {
                BuilderArrayPayload array = (BuilderArrayPayload) payload;
                out.addInstruction(new BuilderArrayPayload(array.getElementWidth(), array.getArrayElements()));
            } else if (payload instanceof BuilderPackedSwitchPayload) {
                List<? extends BuilderSwitchElement> old =
                        ((BuilderPackedSwitchPayload) payload).getSwitchElements();
                if (old.isEmpty()) {
                    out.addInstruction(new BuilderPackedSwitchPayload(0, new ArrayList<Label>()));
                } else {
                    List<Label> targets = new ArrayList<>(old.size());
                    for (BuilderSwitchElement element : old) {
                        int target = element.getTarget().getLocation().getIndex();
                        targets.add(out.getLabel(blockLabel(target)));
                    }
                    out.addInstruction(new BuilderPackedSwitchPayload(old.get(0).getKey(), targets));
                }
            } else if (payload instanceof BuilderSparseSwitchPayload) {
                List<SwitchLabelElement> elements = new ArrayList<>();
                for (BuilderSwitchElement element :
                        ((BuilderSparseSwitchPayload) payload).getSwitchElements()) {
                    int target = element.getTarget().getLocation().getIndex();
                    elements.add(new SwitchLabelElement(element.getKey(),
                            out.getLabel(blockLabel(target))));
                }
                out.addInstruction(new BuilderSparseSwitchPayload(elements));
            } else {
                reorderFailure = TransformationOutcome.Reason.UNSUPPORTED;
                return null;
            }
        }

        // 第二层字符 payload 同样放在尾部数据区，dexlib2 负责对齐与 31t 偏移。
        for (SwitchPaddingPlan plan : switchPlans.values()) {
            out.addLabel(switchCharPayloadLabel(plan.switchIndex));
            List<SwitchLabelElement> elements = new ArrayList<>(
                    plan.realCases.size() + plan.fakeCases.size());
            for (int ri = 0; ri < plan.realCases.size(); ri++) {
                elements.add(new SwitchLabelElement(plan.realCases.get(ri).symbolKey,
                        out.getLabel(switchRealLabel(plan.switchIndex, ri))));
            }
            for (int fi = 0; fi < plan.fakeCases.size(); fi++) {
                elements.add(new SwitchLabelElement(plan.fakeCases.get(fi).symbolKey,
                        out.getLabel(switchFakeLabel(plan.switchIndex, fi))));
            }
            elements.sort((a, b) -> Integer.compare(a.key, b.key));
            out.addInstruction(new BuilderSparseSwitchPayload(elements));
        }

        // 重建 try 表：对每个 try 区间与之相交的每个块，登记 [blk(b), blockEnd(b)) -> handler。
        for (int[] tr : tryRanges) {
            int sIdx = tr[0], eIdx = tr[1], hIdx = tr[2], typeSlot = tr[3];
            int handlerStart = blocks.get(blockOfIndex[hIdx])[0];
            int idx = sIdx;
            while (idx < eIdx) {
                int b = blockOfIndex[idx];
                int bStart = blocks.get(b)[0];
                int bEnd = blocks.get(b)[1];
                Label from = out.getLabel(blockLabel(bStart));
                Label to = out.getLabel(blockEndLabel(bStart));
                Label handler = out.getLabel(blockLabel(handlerStart));
                TypeReference type = tryTypes.get(typeSlot);
                if (type != null) out.addCatch(type, from, to, handler);
                else out.addCatch(from, to, handler);
                idx = bEnd;
            }
        }

        return out.getMethodImplementation();
    }

    /** 为原始 switch 建立“真实 key -> 随机 32 位 key -> 可见 char key”双层映射。 */
    private Map<Integer, SwitchPaddingPlan> buildSwitchPaddingPlans(
            List<BuilderInstruction> insns, int execN, long seed) {
        Map<Integer, Integer> payloadUseCount = new LinkedHashMap<>();
        for (int i = 0; i < execN; i++) {
            if (!isSwitchInstruction(insns.get(i).getOpcode())) continue;
            Integer payloadIndex = builderBranchTargetIndex(insns.get(i));
            if (payloadIndex != null) payloadUseCount.merge(payloadIndex, 1, Integer::sum);
        }

        int depth = Math.max(1, config.depth);
        int remainingCaseBudget = depth <= 1 ? 48 : (depth == 2 ? 160 : 240);
        Map<Integer, SwitchPaddingPlan> plans = new LinkedHashMap<>();
        Set<Integer> claimedPayloads = new HashSet<>();
        for (int i = 0; i < execN && remainingCaseBudget > 0; i++) {
            BuilderInstruction switchInsn = insns.get(i);
            if (!isSwitchInstruction(switchInsn.getOpcode()) || i + 1 >= execN) continue;
            Integer payloadIndex = builderBranchTargetIndex(switchInsn);
            if (payloadIndex == null || payloadIndex < execN || payloadIndex >= insns.size()
                    || payloadUseCount.getOrDefault(payloadIndex, 0) != 1
                    || !claimedPayloads.add(payloadIndex)) {
                continue;
            }
            BuilderInstruction payload = insns.get(payloadIndex);
            if (!(payload instanceof com.android.tools.smali.dexlib2.builder.BuilderSwitchPayload)) {
                continue;
            }
            List<? extends BuilderSwitchElement> old =
                    ((com.android.tools.smali.dexlib2.builder.BuilderSwitchPayload) payload)
                            .getSwitchElements();
            // 超大原生 switch 已经足够复杂；双层 dispatcher 再复制数百项只会制造异常体积。
            if (old.isEmpty() || old.size() > 95 || old.size() > remainingCaseBudget) continue;

            Random random = new Random(mix64(seed ^ (0x9E3779B97F4A7C15L * (i + 1L))));
            int target = targetSwitchCaseCount(depth, old.size(), random);
            target = Math.max(old.size(), Math.min(target, remainingCaseBudget));
            List<Integer> symbols = allocateDecompilerVisibleSymbolKeys(target, random);
            SwitchKeyEncoder encoder = createSwitchKeyEncoder(old, random);
            if (encoder == null) continue;
            List<SwitchCasePlan> realCases = new ArrayList<>(old.size());
            Set<Integer> occupiedEncodedKeys = new HashSet<>();
            for (BuilderSwitchElement element : old) {
                // 伪 encoded key 也避开原始值，避免反编译结果偶然又出现 case 1..6。
                occupiedEncodedKeys.add(element.getKey());
            }
            for (int ci = 0; ci < old.size(); ci++) {
                BuilderSwitchElement element = old.get(ci);
                int targetIndex = element.getTarget().getLocation().getIndex();
                if (targetIndex < 0 || targetIndex >= execN) {
                    realCases.clear();
                    break;
                }
                realCases.add(new SwitchCasePlan(
                        element.getKey(), encoder.encode(element.getKey()),
                        symbols.get(ci), targetIndex));
                occupiedEncodedKeys.add(encoder.encode(element.getKey()));
            }
            if (realCases.size() != old.size()) continue;
            List<Integer> fakeEncodedKeys = allocateRandomSparseKeys(
                    target - old.size(), occupiedEncodedKeys, random);
            List<SwitchFakeCasePlan> fakeCases = new ArrayList<>(fakeEncodedKeys.size());
            for (int fi = 0; fi < fakeEncodedKeys.size(); fi++) {
                fakeCases.add(new SwitchFakeCasePlan(
                        fakeEncodedKeys.get(fi), symbols.get(old.size() + fi)));
            }
            int selectorReg = ((OneRegisterInstruction) switchInsn).getRegisterA();
            SwitchPaddingPlan plan = new SwitchPaddingPlan(
                    i, payloadIndex, selectorReg, i + 1, encoder, realCases, fakeCases);
            plans.put(i, plan);
            remainingCaseBudget -= target;
            paddedSwitches++;
            switchCasesBefore += old.size();
            switchCasesAfter += target;
            fakeSwitchCases += fakeCases.size();
            symbolSwitchCases += target;
        }
        return plans;
    }

    /**
     * XOR/add 是可逆的；乘以奇数在 2^32 环上也可逆。四步组合对所有 int 是一一映射，
     * 因此伪 encoded key 只会拦截原本应走 default 的 selector，最终再跳 default 不改语义。
     */
    private static SwitchKeyEncoder createSwitchKeyEncoder(
            List<? extends BuilderSwitchElement> originalCases, Random random) {
        Set<Integer> rawKeys = new HashSet<>();
        for (BuilderSwitchElement element : originalCases) rawKeys.add(element.getKey());
        for (int attempt = 0; attempt < 128; attempt++) {
            int xorHead = randomNonZeroSignedShort(random);
            int multiplier = 3 + random.nextInt(16383) * 2; // 3..32767 奇数
            int addend = randomNonZeroSignedShort(random);
            int xorTail = randomNonZeroSignedShort(random);
            SwitchKeyEncoder encoder = new SwitchKeyEncoder(
                    xorHead, multiplier, addend, xorTail);
            Set<Integer> encodedKeys = new HashSet<>();
            boolean safe = true;
            for (BuilderSwitchElement element : originalCases) {
                int encoded = encoder.encode(element.getKey());
                if ((encoded >= -65535 && encoded <= 65535)
                        || rawKeys.contains(encoded) || !encodedKeys.add(encoded)) {
                    safe = false;
                    break;
                }
            }
            if (safe) return encoder;
        }
        return null;
    }

    private static int randomNonZeroSignedShort(Random random) {
        int value;
        do {
            value = (short) random.nextInt(1 << 16);
        } while (value == 0);
        return value;
    }

    /** 生成同时含正数、负数和接近 int 极值的唯一 sparse key。 */
    private static List<Integer> allocateRandomSparseKeys(
            int count, Set<Integer> occupied, Random random) {
        List<Integer> result = new ArrayList<>(count);
        if (count > 0) {
            addSparseKey(result, occupied,
                    Integer.MIN_VALUE + random.nextInt(1 << 20));
        }
        if (count > 1) {
            addSparseKey(result, occupied,
                    Integer.MAX_VALUE - random.nextInt(1 << 20));
        }
        while (result.size() < count) {
            int candidate = random.nextInt();
            if (candidate >= -65535 && candidate <= 65535) continue;
            addSparseKey(result, occupied, candidate);
        }
        Collections.shuffle(result, random);
        return result;
    }

    private static void addSparseKey(
            List<Integer> result, Set<Integer> occupied, int candidate) {
        if (occupied.add(candidate)) result.add(candidate);
    }

    private static int targetSwitchCaseCount(int depth, int realCount, Random random) {
        int min;
        int max;
        if (depth <= 1) {
            min = 12;
            max = 24;
        } else if (depth == 2) {
            // 默认 MEDIUM：按用户要求把常见 3~10 case 扩到约 50~80。
            min = 50;
            max = 80;
        } else {
            min = 80;
            // JADX 默认只把 ASCII 32..126 的 char switch key 渲染成字符字面量。
            // 这一可见空间共 95 个唯一 key，仍落在 HIGH 的 80~100 设计范围。
            max = 95;
        }
        int requested = min + random.nextInt(max - min + 1);
        return Math.max(realCount, requested);
    }

    /**
     * NullProguard 的 ONameFactory 用非常规 Unicode 字符组合标识符。switch key 仍只能是
     * 32 位整数，而 JADX 1.5.x 默认只会把 ASCII 32..126 显示成 char 字面量：私有区
     * U+E814/U+E811/U+E813 会重新显示为十进制数。因此这里使用同样的“字符空间编码”
     * 思路，但优先分配 !/@/~ 等 ASCII 标点，再用其余可见字符补足到 95 个。
     */
    private static List<Integer> allocateDecompilerVisibleSymbolKeys(int count, Random random) {
        if (count < 0 || count > 95) {
            throw new IllegalArgumentException("visible switch key count out of range: " + count);
        }
        List<Integer> punctuation = new ArrayList<>();
        List<Integer> alphanumeric = new ArrayList<>();
        for (int key = 0x20; key <= 0x7E; key++) {
            if (Character.isLetterOrDigit((char) key)) alphanumeric.add(key);
            else punctuation.add(key);
        }
        Collections.shuffle(punctuation, random);
        Collections.shuffle(alphanumeric, random);
        punctuation.addAll(alphanumeric);
        return new ArrayList<>(punctuation.subList(0, count));
    }

    /** 第一层：对原 selector 做可逆 32 位编码，直接进入随机正负 key sparse-switch。 */
    private static void emitPaddedSwitch(MethodImplementationBuilder out,
                                         SwitchPaddingPlan plan, int scratchReg) {
        out.addInstruction(new BuilderInstruction22x(
                Opcode.MOVE_FROM16, scratchReg, plan.selectorReg));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.XOR_INT_LIT16, scratchReg, scratchReg, plan.encoder.xorHead));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.MUL_INT_LIT16, scratchReg, scratchReg, plan.encoder.multiplier));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.ADD_INT_LIT16, scratchReg, scratchReg, plan.encoder.addend));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.XOR_INT_LIT16, scratchReg, scratchReg, plan.encoder.xorTail));
        out.addInstruction(new BuilderInstruction31t(
                Opcode.SPARSE_SWITCH, scratchReg, out.getLabel(payloadLabel(plan.payloadIndex))));
        out.addInstruction(new BuilderInstruction10t(
                Opcode.GOTO, out.getLabel(blockLabel(plan.defaultIndex))));
    }

    /** 外层 case 把随机 32 位 key 映射到唯一可见 char，并经与真实路径同形的可逆噪声进入内层。 */
    private static void emitSwitchSymbolBridge(MethodImplementationBuilder out,
                                               String entryLabel, String alternateLabel,
                                               int scratchReg, int symbolKey,
                                               long seed, int salt, Label destination) {
        out.addLabel(entryLabel);
        emitIntConst(out, scratchReg, symbolKey);
        emitSwitchNoise(out, alternateLabel, scratchReg, seed, salt, destination);
    }

    /** 真实/伪 case 使用相同形状的可逆整数噪声，只改变独立 scratch。 */
    private static void emitSwitchTrampoline(MethodImplementationBuilder out,
                                             String entryLabel, String alternateLabel,
                                             int scratchReg, long seed, int salt,
                                             Label destination) {
        out.addLabel(entryLabel);
        emitSwitchNoise(out, alternateLabel, scratchReg, seed, salt, destination);
    }

    private static void emitSwitchNoise(MethodImplementationBuilder out,
                                        String alternateLabel, int scratchReg,
                                        long seed, int salt, Label destination) {
        long mixed = mix64(seed + 0x9E3779B97F4A7C15L * (salt + 1L));
        // lit16 的正数上限是 32767，不能生成 32768。
        int mask = 1 + (int) ((mixed >>> 16) % 32767L);
        int delta = 1 + (int) ((mixed >>> 40) & 0x07ffL);
        out.addInstruction(new BuilderInstruction22s(
                Opcode.XOR_INT_LIT16, scratchReg, scratchReg, mask));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.ADD_INT_LIT16, scratchReg, scratchReg, delta));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.ADD_INT_LIT16, scratchReg, scratchReg, -delta));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.XOR_INT_LIT16, scratchReg, scratchReg, mask));
        out.addInstruction(new BuilderInstruction21t(
                Opcode.IF_EQZ, scratchReg, out.getLabel(alternateLabel)));
        out.addInstruction(new BuilderInstruction10t(Opcode.GOTO, destination));
        out.addLabel(alternateLabel);
        out.addInstruction(new BuilderInstruction22s(
                Opcode.ADD_INT_LIT16, scratchReg, scratchReg, delta));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.ADD_INT_LIT16, scratchReg, scratchReg, -delta));
        out.addInstruction(new BuilderInstruction10t(Opcode.GOTO, destination));
    }

    private static void emitIntConst(MethodImplementationBuilder out, int register, int value) {
        if (value >= -8 && value <= 7 && register <= 15) {
            out.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, register, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            out.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, register, value));
        } else {
            out.addInstruction(new BuilderInstruction31i(Opcode.CONST, register, value));
        }
    }

    private static String switchOuterRealLabel(int switchIndex, int caseIndex) {
        return "SOR" + switchIndex + '_' + caseIndex;
    }
    private static String switchOuterFakeLabel(int switchIndex, int caseIndex) {
        return "SOF" + switchIndex + '_' + caseIndex;
    }
    private static String switchOuterAltLabel(int switchIndex, int caseIndex, boolean fake) {
        return (fake ? "SOFA" : "SORA") + switchIndex + '_' + caseIndex;
    }
    private static String switchCharDispatchLabel(int switchIndex) { return "SCD" + switchIndex; }
    private static String switchCharPayloadLabel(int switchIndex) { return "SCP" + switchIndex; }
    private static String switchRealLabel(int switchIndex, int caseIndex) {
        return "SR" + switchIndex + '_' + caseIndex;
    }
    private static String switchFakeLabel(int switchIndex, int caseIndex) {
        return "SF" + switchIndex + '_' + caseIndex;
    }
    private static String switchAltLabel(int switchIndex, int caseIndex, boolean fake) {
        return (fake ? "SFA" : "SRA") + switchIndex + '_' + caseIndex;
    }

    private static final class SwitchCasePlan {
        final int originalKey;
        final int encodedKey;
        final int symbolKey;
        final int targetIndex;

        SwitchCasePlan(int originalKey, int encodedKey, int symbolKey, int targetIndex) {
            this.originalKey = originalKey;
            this.encodedKey = encodedKey;
            this.symbolKey = symbolKey;
            this.targetIndex = targetIndex;
        }
    }

    private static final class SwitchFakeCasePlan {
        final int encodedKey;
        final int symbolKey;

        SwitchFakeCasePlan(int encodedKey, int symbolKey) {
            this.encodedKey = encodedKey;
            this.symbolKey = symbolKey;
        }
    }

    private static final class SwitchKeyEncoder {
        final int xorHead;
        final int multiplier;
        final int addend;
        final int xorTail;

        SwitchKeyEncoder(int xorHead, int multiplier, int addend, int xorTail) {
            this.xorHead = xorHead;
            this.multiplier = multiplier;
            this.addend = addend;
            this.xorTail = xorTail;
        }

        int encode(int value) {
            int encoded = value ^ xorHead;
            encoded *= multiplier;
            encoded += addend;
            return encoded ^ xorTail;
        }
    }

    private static final class SwitchPaddingPlan {
        final int switchIndex;
        final int payloadIndex;
        final int selectorReg;
        final int defaultIndex;
        final SwitchKeyEncoder encoder;
        final List<SwitchCasePlan> realCases;
        final List<SwitchFakeCasePlan> fakeCases;

        SwitchPaddingPlan(int switchIndex, int payloadIndex, int selectorReg, int defaultIndex,
                          SwitchKeyEncoder encoder, List<SwitchCasePlan> realCases,
                          List<SwitchFakeCasePlan> fakeCases) {
            this.switchIndex = switchIndex;
            this.payloadIndex = payloadIndex;
            this.selectorReg = selectorReg;
            this.defaultIndex = defaultIndex;
            this.encoder = encoder;
            this.realCases = realCases;
            this.fakeCases = fakeCases;
        }
    }

    private void resetSwitchPaddingStats() {
        paddedSwitches = 0;
        switchCasesBefore = 0;
        switchCasesAfter = 0;
        fakeSwitchCases = 0;
        symbolSwitchCases = 0;
        reorderScratchAdded = 0;
    }

    private static boolean containsSwitchInstruction(MethodImplementation implementation) {
        for (Instruction instruction : implementation.getInstructions()) {
            if (isSwitchInstruction(instruction.getOpcode())) return true;
        }
        return false;
    }

    private static long mix64(long value) {
        value = (value ^ (value >>> 30)) * 0xBF58476D1CE4E5B9L;
        value = (value ^ (value >>> 27)) * 0x94D049BB133111EBL;
        return value ^ (value >>> 31);
    }

    private static String blockEndLabel(int originalStartIndex) { return "BE" + originalStartIndex; }
    private static String payloadLabel(int originalIndex) { return "P" + originalIndex; }

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
        Opcode op = insn.getOpcode();
        if (op == Opcode.FILL_ARRAY_DATA || op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH) {
            int register = ((OneRegisterInstruction) insn).getRegisterA();
            return new BuilderInstruction31t(op, register, out.getLabel(payloadLabel(tgt)));
        }
        Label lbl = out.getLabel(blockLabel(tgt));
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
        return computeBlocks(insns, null);
    }

    /** 计算基本块 [start,end) 列表；extraLeader 指定额外块首（如 try 边界/handler）。分支目标不可解析返回 null。 */
    private List<int[]> computeBlocks(List<BuilderInstruction> insns, boolean[] extraLeader) {
        return computeBlocks(insns, extraLeader, insns.size());
    }

    private List<int[]> computeBlocks(List<BuilderInstruction> insns, boolean[] extraLeader, int execN) {
        int n = Math.min(execN, insns.size());
        if (n == 0) return new ArrayList<>();
        boolean[] leader = new boolean[n];
        leader[0] = true;
        for (int i = 0; i < n; i++) {
            if (extraLeader != null && extraLeader[i]) leader[i] = true;
            BuilderInstruction insn = insns.get(i);
            Opcode op = insn.getOpcode();
            if (isSwitchInstruction(op)) {
                if (i + 1 < n) leader[i + 1] = true;
                Integer payloadIndex = builderBranchTargetIndex(insn);
                if (payloadIndex == null || payloadIndex < n || payloadIndex >= insns.size()) return null;
                BuilderInstruction payload = insns.get(payloadIndex);
                if (!(payload instanceof com.android.tools.smali.dexlib2.builder.BuilderSwitchPayload)) return null;
                for (BuilderSwitchElement element :
                        ((com.android.tools.smali.dexlib2.builder.BuilderSwitchPayload) payload).getSwitchElements()) {
                    int target = element.getTarget().getLocation().getIndex();
                    if (target < 0 || target >= n) return null;
                    leader[target] = true;
                }
            } else if (isBranch(op)) {
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
        return isGoto(op) || isConditional(op) || isSwitchInstruction(op);
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

    private static boolean isPayload(Opcode op) {
        return op == Opcode.PACKED_SWITCH_PAYLOAD || op == Opcode.SPARSE_SWITCH_PAYLOAD
                || op == Opcode.ARRAY_PAYLOAD;
    }

    private static boolean isSwitchInstruction(Opcode op) {
        return op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH;
    }

    /** packed/sparse-switch（含其 payload）。关闭 payload 重定位时用于保守跳过。 */
    private static boolean isSwitch(Opcode op) {
        switch (op) {
            case PACKED_SWITCH: case SPARSE_SWITCH:
            case PACKED_SWITCH_PAYLOAD: case SPARSE_SWITCH_PAYLOAD:
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

    private long stableSeed(Method method, MethodImplementation impl, int n, int blocks) {
        long h = config.seed ^ 1125899906842597L;
        h = mixString(h, method.getDefiningClass());
        h = mixString(h, method.getName());
        h = mixString(h, method.getReturnType());
        for (CharSequence parameter : method.getParameterTypes()) {
            h = mixString(h, parameter == null ? "" : parameter.toString());
        }
        h = 31 * h + n;
        h = 31 * h + blocks;
        h = 31 * h + impl.getRegisterCount();
        // 混入 opcode 与分支目标形状；同签名但代码变化时也会得到不同布局。
        MutableMethodImplementation work = new MutableMethodImplementation(impl);
        for (BuilderInstruction insn : work.getInstructions()) {
            h = 31 * h + insn.getOpcode().ordinal();
            Integer target = builderBranchTargetIndex(insn);
            if (target != null) h = 31 * h + target;
        }
        return h;
    }

    private static long mixString(long h, String value) {
        if (value == null) return 31 * h;
        for (int i = 0; i < value.length(); i++) h = 31 * h + value.charAt(i);
        return h;
    }
}
