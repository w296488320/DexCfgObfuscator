package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderTryBlock;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.*;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21t;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22t;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * ControlFlowFlattener —— 控制流平坦化（dispatcher + switch 状态机）。
 *
 * 目标：生成**不可归约的控制流图**，让 jadx/JEB 无法把控制流线性化还原成可读 Java，
 * 只能吐 while(true)+switch 或 goto+label 原样。相比“基本块重排”，平坦化对简单方法同样有效。
 *
 * 结构（原寄存器整体 +4，见 RegisterShifter）：
 *   v0/v1 = encoded state 的 XOR shares，v2 = 短生命周期重建值，v3 = rolling route
 *   :dispatcher_r  sparse-switch decode(v0 XOR v1), :payload_r
 *   :alias_i_a / :alias_i_b  两条均可达、语义等价的 trampoline
 *   :blk_i ...（块尾更新两个 share，再进入目标区域 dispatcher；return/throw 原样退出）
 *
 * try/catch：try 边界与 handler 目标一定落在基本块首（切块时强制成 leader）。每个 try 区间
 * [s,e) 可能跨多个块，对每个与之相交的块 b，登记一条 catch：覆盖 blk(b) 的**真实指令段**
 * [blk(b), blkEnd(b))，handler 指向 blk(handlerBlock)。块尾我们追加的 const/goto 粘合指令
 * 放在 blkEnd(b) 之后、不在保护范围内（const/goto 不会抛异常，语义等价）。
 *
 * 安全：任一环节异常都抛出，由上层 flatten 回退不混淆，绝不产出非法 dex。
 */
final class ControlFlowFlattener {

    static final int ADDED_REGISTERS = 4;

    private final ObfuscatorConfig config;
    private final ObfuscatorStats stats;
    /** 顺序长段每隔多少条强制切一块（<=0 不切）。制造更多基本块以增强 dispatcher。 */
    private final int splitInterval;

    ControlFlowFlattener(ObfuscatorConfig config, ObfuscatorStats stats) {
        this.config = config;
        this.stats = stats;
        // depth 越大切得越密（块更多、更难读）。LOW/MEDIUM/HIGH 分别约每 4/3/2 条切一刀。
        int d = Math.max(1, config.depth);
        this.splitInterval = Math.max(2, 5 - d);
    }

    private int dispatcherRegions;
    private int reachableAliasCases;

    private static String dispatcher(int region) { return "dispatcher" + region; }
    private static String payload(int region) { return "payload" + region; }
    private static String blk(int id) { return "blk" + id; }
    private static String blkEnd(int id) { return "blkEnd" + id; }
    private static String taken(int id) { return "taken" + id; }
    private static String alias(int block, int variant) { return "alias" + block + '_' + variant; }
    private static String routeAlt(int salt) { return "routeAlt" + salt; }
    private static String moveExc(int id) { return "moveExc" + id; }
    private static String arrData(int id) { return "arrData" + id; }

    /**
     * 发射一条“块体内”指令到 out：
     *   - fill-array-data（31t）是 offset 指令，其目标 Label 绑定在旧 impl(work) 上，直接复用会
     *     导致新体里无法解析。故按“目标 payload 的原索引”重绑到 out 上的 arrData(origIdx) 标签。
     *   - 其余指令原样加入。
     */
    private static void emitBody(MethodImplementationBuilder out, BuilderInstruction insn) {
        if (insn.getOpcode() == Opcode.FILL_ARRAY_DATA) {
            int tgt = targetIndex(insn); // payload 的原索引（work 内）
            int reg = ((com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction) insn).getRegisterA();
            out.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, reg, out.getLabel(arrData(tgt))));
            return;
        }
        out.addInstruction(insn);
    }

    MethodImplementation flatten(Method method, MethodImplementation impl, long seed,
                                 int paramRegisterCount) {
        MutableMethodImplementation src = new MutableMethodImplementation(impl);

        if (src.getRegisterCount() + ADDED_REGISTERS > config.maxRegisters) {
            throw new IllegalStateException("register budget exceeded: " + src.getRegisterCount()
                    + "+" + ADDED_REGISTERS + " > " + config.maxRegisters);
        }

        // ---- 阶段 1：寄存器整体 +4 ----
        // v0/v1 是 XOR 状态分享，v2 只在 dispatcher 短暂重建状态并兼作 scratch，v3 是
        // 路径相关的 rolling route。不存在一个贯穿全方法、可直接做 def-use 回溯的 state vreg。
        RegisterShifter.Result shifted = RegisterShifter.shift(src, ADDED_REGISTERS);
        MutableMethodImplementation work =
                new MutableMethodImplementation(shifted.builder.getMethodImplementation());
        int stateShareA = 0;
        int stateShareB = 1;
        int workReg = 2;
        int routeReg = 3;
        int newRc = shifted.newRegisterCount;

        List<BuilderInstruction> insns = work.getInstructions();
        int n = insns.size();

        // ---- 识别“尾部数据区”：array-data（fill-array-data 的 payload）总是被 d8/dx 排在
        // 方法末尾（最后一条 return 之后），用 nop 做 4 字节对齐。字符串加密(StringFog)会把每个
        // 字符串字面量变成 new byte[]{...}+fill-array-data，从而给几乎所有“有意思的方法”都带上
        // 这些 payload。旧逻辑遇到 fill-array-data 直接跳过整方法 => 大量方法未混淆。
        // 这里改为：把 [execN, n) 的 array-data payload 抽出、末尾按 Label 重新发射，dexlib2 自动
        // 对齐；fill-array-data 指令留在原块内（它是“落空”指令，执行后顺序到下一条），只需把它的
        // 目标 Label 改绑到重定位后的 payload。
        // 安全：只接受 array-data payload 作为可重定位数据；若尾部数据区里混有非 payload/非 nop 的
        // 可执行指令（不符合“payload 恒在尾部”的假设），或出现 packed/sparse-switch，则抛出 => 上层
        // 回退，绝不产出非法 dex。
        int execN = n;
        for (int i = 0; i < n; i++) {
            if (insns.get(i).getOpcode() == Opcode.ARRAY_PAYLOAD) { execN = i; break; }
        }
        // d8/dx 会在 array-data payload 前插入 nop 做 4 字节对齐。这些 nop 属于“数据区”而非可执行
        // 代码——若把它们留在可执行区，末块会以 nop 落空、其后继落到数据区(blockOfIndex==k)，导致
        // stateId[k] 越界。故把紧邻首个 payload 之前的对齐 nop 一并并入数据区。
        while (execN > 0 && insns.get(execN - 1).getOpcode() == Opcode.NOP) execN--;
        List<Integer> payloadIndices = new ArrayList<>();
        for (int i = execN; i < n; i++) {
            Opcode op = insns.get(i).getOpcode();
            if (op == Opcode.ARRAY_PAYLOAD) {
                payloadIndices.add(i);
            } else if (op == Opcode.NOP) {
                // 对齐用 spacer，忽略（dexlib2 重排后会自行按需插入对齐 nop）。
            } else {
                // 尾部数据区出现可执行指令 => 不符合“payload 恒在尾部”的假设，放弃（保安全）。
                throw new IllegalStateException("executable insn in trailing data region: " + op);
            }
        }
        if (execN < 2) throw new IllegalStateException("no executable region to flatten");

        // try 边界与 handler 收集为“额外 leader”，保证它们落在块首。
        List<? extends TryBlock<? extends ExceptionHandler>> tries = work.getTryBlocks();
        boolean[] extraLeader = new boolean[n + 1];
        List<int[]> tryRanges = new ArrayList<>();   // {startIdx, endIdx, handlerIdx, typeSlot}
        List<TypeReference> tryTypes = new ArrayList<>();
        List<String> tryTypeStrs = new ArrayList<>();
        if (tries != null) {
            for (TryBlock<? extends ExceptionHandler> tb : tries) {
                int sIdx = ((BuilderTryBlock) tb).start.getLocation().getIndex();
                int eIdx = ((BuilderTryBlock) tb).end.getLocation().getIndex();
                if (sIdx < 0 || eIdx > n || sIdx >= eIdx) throw new IllegalStateException("bad try range");
                markLeader(extraLeader, sIdx, n);
                markLeader(extraLeader, eIdx, n);
                for (ExceptionHandler h : tb.getExceptionHandlers()) {
                    int hIdx = ((com.android.tools.smali.dexlib2.builder.BuilderExceptionHandler)
                            h).getHandler().getLocation().getIndex();
                    markLeader(extraLeader, hIdx, n);
                    tryRanges.add(new int[]{sIdx, eIdx, hIdx, tryTypes.size()});
                    tryTypes.add(h.getExceptionTypeReference());
                    tryTypeStrs.add(h.getExceptionType());
                }
            }
        }

        // ---- 基本块切分（只切分可执行区 [0, execN)；尾部 array-data 数据区不参与）----
        List<int[]> blocks = computeBlocks(work, extraLeader, execN);
        if (blocks == null) throw new IllegalStateException("cannot compute blocks");
        int k = blocks.size();
        if (k < 2) throw new IllegalStateException("too few blocks to flatten");

        int[] blockOfIndex = new int[n + 1];
        for (int b = 0; b < k; b++) {
            for (int i = blocks.get(b)[0]; i < blocks.get(b)[1]; i++) blockOfIndex[i] = b;
        }
        // execN..n（尾部数据区）归属“末块之后”，其 blockOfIndex 不会被分发使用。
        for (int i = execN; i <= n; i++) blockOfIndex[i] = k;

        // 标记“handler 入口块”：其首指令是 move-exception。ART 要求 move-exception 只能被
        // 异常边到达、且必须是 handler 的第一条指令。平坦化的 dispatcher 用普通 switch 边跳入
        // 会触发 "invalid use of move-exception"。因此这些块**特殊发射**：
        //   moveExc(b): move-exception vX; (设置进入真实续体的 state) goto dispatcher   <- addCatch 指向这里
        //   blk(b):     move-exception 之后的真实指令（作为普通块，经 dispatcher 到达）
        boolean[] isHandlerEntry = new boolean[k];
        int[] handlerFirstReg = new int[k];
        for (int b = 0; b < k; b++) {
            int s0 = blocks.get(b)[0];
            BuilderInstruction first = insns.get(s0);
            if (first.getOpcode() == Opcode.MOVE_EXCEPTION) {
                isHandlerEntry[b] = true;
                handlerFirstReg[b] = ((com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction) first).getRegisterA();
            }
        }

        // 物理块乱序后再均匀分配到 2~4 个独立 region。每个 region 有自己的 dispatcher、
        // payload、编码常量和稀疏 key 空间；跨 region 的真实边直接进入目标 region 的 dispatcher。
        Integer[] order = new Integer[k];
        for (int i = 0; i < k; i++) order[i] = i;
        Random rnd = new Random(seed);
        for (int i = k - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            Integer t = order[i]; order[i] = order[j]; order[j] = t;
        }
        int regionCount = Math.min(k, Math.max(2, Math.min(4, config.depth + 1)));
        dispatcherRegions = regionCount;
        int[] regionOfBlock = new int[k];
        List<List<Integer>> regionBlocks = new ArrayList<>(regionCount);
        for (int r = 0; r < regionCount; r++) regionBlocks.add(new ArrayList<>());
        for (int pos = 0; pos < k; pos++) {
            int b = order[pos];
            int region = pos % regionCount;
            regionOfBlock[b] = region;
            regionBlocks.get(region).add(b);
        }

        // 选择一组真实目标块，为每个目标建立两个等价 alias case。入口块必选，保证每次正常
        // 执行都会经过至少一个 alias；其它 alias 随真实 CFG 路径可达，不再依赖恒假谓词。
        boolean[] aliasEnabled = new boolean[k];
        int aliasTargetCount = Math.min(k, 2 + Math.max(1, config.depth) * 2);
        List<Integer> aliasCandidates = new ArrayList<>();
        for (int b = 1; b < k; b++) aliasCandidates.add(b);
        Collections.shuffle(aliasCandidates, new Random(seed ^ 0xA0761D6478BD642FL));
        aliasEnabled[0] = true;
        for (int i = 0; i < aliasTargetCount - 1; i++) {
            aliasEnabled[aliasCandidates.get(i)] = true;
        }
        reachableAliasCases = aliasTargetCount * 2;

        int[] stateKey = new int[k];
        int[] aliasKeyA = new int[k];
        int[] aliasKeyB = new int[k];
        Random stateRnd = new Random(seed ^ 0xD1B54A32D192ED03L);
        Set<Integer> usedKeys = new HashSet<>();
        for (int b = 0; b < k; b++) {
            stateKey[b] = nextUniqueKey32(stateRnd, usedKeys);
            if (aliasEnabled[b]) {
                aliasKeyA[b] = nextUniqueKey32(stateRnd, usedKeys);
                aliasKeyB[b] = nextUniqueKey32(stateRnd, usedKeys);
            }
        }

        int[] K1 = new int[regionCount];
        int[] K2 = new int[regionCount];
        int[] K3 = new int[regionCount];
        int[] encoderTemplate = new int[regionCount];
        for (int r = 0; r < regionCount; r++) {
            Random keyRnd = new Random(mix64(seed ^ (0x9E3779B97F4A7C15L * (r + 1L))));
            K1[r] = 1 + keyRnd.nextInt(0x3fff);
            K2[r] = 1 + keyRnd.nextInt(0x1fff);
            K3[r] = 1 + keyRnd.nextInt(0x0fff);
            encoderTemplate[r] = config.enableMultiTemplate
                    ? (int) (mix64(seed + r) & 7L) : 0;
        }

        MethodImplementationBuilder out = new MethodImplementationBuilder(newRc);

        // 与 reorder 路径共用的低碰撞 V1 幂等标记。即使 state/evidence sidecar 被误删，
        // 下一次也能识别已经变换的方法，避免对 flattened CFG 再次套娃。
        Label transformedEntry = out.getLabel("cfgTransformedEntry");
        ObfuscationMarker.emitV1(out, transformedEntry);
        out.addLabel("cfgTransformedEntry");

        // 入口：先把所有非参数寄存器预初始化为 0，再进 dispatcher。
        // 原因：平坦化后每个块都从 dispatcher 可达，破坏了“定义支配使用”，ART 校验器会因
        // “寄存器在某条到达路径上未定义”而 VerifyError。预置为 0 使每个寄存器入口即“已定义”，
        // 真实赋值再覆盖，语义不变、校验通过。
        // 关键：wide（long/double）寄存器必须用 const-wide/16 预置（把 r:r+1 一起定型为 Long），
        // 否则用窄 const 预置会和后续 wide 使用冲突（"Integer but expected Long (Low Half)"）。
        // 参数寄存器（最高的 P 个）不能覆盖，否则丢参数值。
        boolean[] wideLow = collectWideLowRegisters(insns, newRc);
        int paramRegs = paramRegisterCount;
        int firstParam = newRc - paramRegs;
        int rgi = 0;
        while (rgi < firstParam) {
            if (rgi < ADDED_REGISTERS) { rgi++; continue; }
            if (wideLow[rgi]) {
                // 该寄存器是某个 wide 值的低半，用 const-wide/16 覆盖 rgi:rgi+1。
                // 若 rgi+1 触及参数区则放弃（避免覆盖参数），退回窄置零。
                if (rgi + 1 < firstParam) {
                    emitZeroWide(out, rgi);
                    rgi += 2;
                    continue;
                }
            }
            emitZero(out, rgi);
            rgi++;
        }

        // 四个控制寄存器全部显式定型为 int。route 优先混入真实 int 参数；无合适参数时仍会
        // 随实际 CFG 路径和上一状态分享持续滚动，alias 选择不是恒真/恒假的数学谓词。
        emitZero(out, stateShareA);
        emitZero(out, stateShareB);
        emitZero(out, workReg);
        emitIntConst(out, routeReg, (int) mix64(seed ^ 0xE7037ED1A0B428DBL));
        int routeSource = findIntegralParameterRegister(method, newRc, paramRegisterCount);
        if (routeSource >= 0) {
            out.addInstruction(new BuilderInstruction22x(Opcode.MOVE_FROM16, workReg, routeSource));
            out.addInstruction(new BuilderInstruction23x(
                    Opcode.XOR_INT, routeReg, routeReg, workReg));
        }
        int transitionSalt = 0;

        // 入口也走 reachable alias，确保正常执行路径实际覆盖干扰 case。
        transitionSalt = emitTransition(out, 0, stateShareA, stateShareB, workReg, routeReg,
                regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                encoderTemplate, K1, K2, K3, seed, transitionSalt);

        // 每个区域独立重建 stateShareA XOR stateShareB，再用本区域的模板解码。
        for (int r = 0; r < regionCount; r++) {
            out.addLabel(dispatcher(r));
            out.addInstruction(new BuilderInstruction23x(
                    Opcode.XOR_INT, workReg, stateShareA, stateShareB));
            emitDecode(out, encoderTemplate[r], workReg, K1[r], K2[r], K3[r]);
            out.addInstruction(new BuilderInstruction31t(
                    Opcode.SPARSE_SWITCH, workReg, out.getLabel(payload(r))));
            out.addInstruction(new BuilderInstruction10t(
                    Opcode.GOTO, out.getLabel(dispatcher(r))));
        }

        // 依 order 发射各块
        for (int pos = 0; pos < k; pos++) {
            int b = order[pos];
            int start = blocks.get(b)[0];
            int end = blocks.get(b)[1];

            // handler 入口块：先发射只含 move-exception 的入口（异常边唯一到达），
            // 它把异常对象存入 vX 后设置 state 跳 dispatcher；真实续体作为 blk(b) 普通块。
            if (isHandlerEntry[b]) {
                out.addLabel(moveExc(b));
                out.addInstruction(insns.get(start)); // move-exception vX（块首，异常边到达）
                // 进入“该块 move-exception 之后的续体”，其 state 就是本块 id（blk(b) 指向 start+1）。
                transitionSalt = emitTransition(out, b, stateShareA, stateShareB, workReg,
                        routeReg, regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                        encoderTemplate, K1, K2, K3, seed, transitionSalt);
                // 续体从 start+1 开始；若续体为空（handler 只有 move-exception+跳转），blk(b) 直接接后续逻辑。
            }
            out.addLabel(blk(b));

            int bodyStart = isHandlerEntry[b] ? start + 1 : start;
            for (int i = bodyStart; i < end - 1; i++) {
                emitBody(out, insns.get(i));
            }
            // 边界情况：handler 块只有 move-exception 一条指令（end==start+1）。
            // 此时续体为空，blk(b) 需要一个到“落空后继块”的跳转（下方 last 逻辑处理 end-1==start 的 move-exception，
            // 但我们已单独发射了它），因此这里对空续体单独补 goto 到后继块。
            if (isHandlerEntry[b] && bodyStart >= end) {
                int fallBlk = requireRealBlock(blockOfIndex[end], k);
                transitionSalt = emitTransition(out, fallBlk, stateShareA, stateShareB, workReg,
                        routeReg, regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                        encoderTemplate, K1, K2, K3, seed, transitionSalt);
                out.addLabel(blkEnd(b));
                continue;
            }
            BuilderInstruction last = insns.get(end - 1);
            Opcode lop = last.getOpcode();

            if (isReturn(lop) || lop == Opcode.THROW) {
                emitBody(out, last);
                out.addLabel(blkEnd(b));               // 真实指令段结束
            } else if (isGoto(lop)) {
                out.addLabel(blkEnd(b));               // goto 是控制流，不算“可抛真实指令”
                int tgtBlk = requireRealBlock(blockOfIndex[targetIndex(last)], k);
                transitionSalt = emitTransition(out, tgtBlk, stateShareA, stateShareB, workReg,
                        routeReg, regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                        encoderTemplate, K1, K2, K3, seed, transitionSalt);
            } else if (isConditional(lop)) {
                out.addLabel(blkEnd(b));
                int takenBlk = requireRealBlock(blockOfIndex[targetIndex(last)], k);
                int fallBlk = requireRealBlock(blockOfIndex[end], k);
                out.addInstruction(rebuildConditional(last, out.getLabel(taken(b))));
                transitionSalt = emitTransition(out, fallBlk, stateShareA, stateShareB, workReg,
                        routeReg, regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                        encoderTemplate, K1, K2, K3, seed, transitionSalt);
                out.addLabel(taken(b));
                transitionSalt = emitTransition(out, takenBlk, stateShareA, stateShareB, workReg,
                        routeReg, regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                        encoderTemplate, K1, K2, K3, seed, transitionSalt);
            } else {
                emitBody(out, last);
                out.addLabel(blkEnd(b));
                int fallBlk = requireRealBlock(blockOfIndex[end], k);
                transitionSalt = emitTransition(out, fallBlk, stateShareA, stateShareB, workReg,
                        routeReg, regionOfBlock, stateKey, aliasEnabled, aliasKeyA, aliasKeyB,
                        encoderTemplate, K1, K2, K3, seed, transitionSalt);
            }
        }

        // 两个 alias 都是普通 switch case，并且会被真实 transition 选择。它们只修改专用 route/
        // state-share 寄存器，最后进入同一个真实块，因此对业务寄存器和副作用完全等价。
        for (int b = 0; b < k; b++) {
            if (!aliasEnabled[b]) continue;
            int region = regionOfBlock[b];
            for (int variant = 0; variant < 2; variant++) {
                out.addLabel(alias(b, variant));
                long mixed = mix64(seed + 0x632BE59BD9B4E019L * (b * 2L + variant + 1L));
                int delta = 1 + (int) ((mixed >>> 17) & 0x07ffL);
                if (variant == 0) {
                    out.addInstruction(new BuilderInstruction22s(
                            Opcode.ADD_INT_LIT16, routeReg, routeReg, delta));
                    out.addInstruction(new BuilderInstruction22s(
                            Opcode.XOR_INT_LIT16, routeReg, routeReg,
                            1 + (int) ((mixed >>> 33) & 0x3fffL)));
                } else {
                    out.addInstruction(new BuilderInstruction22s(
                            Opcode.MUL_INT_LIT16, routeReg, routeReg,
                            3 + 2 * (int) ((mixed >>> 41) & 0x03ffL)));
                    out.addInstruction(new BuilderInstruction22s(
                            Opcode.ADD_INT_LIT16, routeReg, routeReg, -delta));
                }
                emitSplitState(out, stateShareA, stateShareB,
                        enc(stateKey[b], encoderTemplate[region], K1[region], K2[region], K3[region]),
                        seed, transitionSalt++);
                out.addInstruction(new BuilderInstruction10t(
                        Opcode.GOTO, out.getLabel(dispatcher(region))));
            }
        }

        // 每个 region 单独拥有一个只含随机 32 位 key 的 sparse payload。
        for (int r = 0; r < regionCount; r++) {
            out.addLabel(payload(r));
            List<com.android.tools.smali.dexlib2.builder.SwitchLabelElement> elements =
                    new ArrayList<>();
            for (int b : regionBlocks.get(r)) {
                elements.add(new com.android.tools.smali.dexlib2.builder.SwitchLabelElement(
                        stateKey[b], out.getLabel(blk(b))));
                if (aliasEnabled[b]) {
                    elements.add(new com.android.tools.smali.dexlib2.builder.SwitchLabelElement(
                            aliasKeyA[b], out.getLabel(alias(b, 0))));
                    elements.add(new com.android.tools.smali.dexlib2.builder.SwitchLabelElement(
                            aliasKeyB[b], out.getLabel(alias(b, 1))));
                }
            }
            elements.sort((a, b) -> Integer.compare(a.key, b.key));
            out.addInstruction(new BuilderSparseSwitchPayload(elements));
        }

        // ---- 重定位尾部 array-data payload：为每个原 payload 打上 arrData(origIdx) 标签、
        // 原样重发（元素宽度/元素不变）。块内的 fill-array-data 已由 emitBody 重绑到这些标签。
        // dexlib2 会为 array-data 自动处理 4 字节对齐（必要时插入 nop）。
        for (int pIdx : payloadIndices) {
            out.addLabel(arrData(pIdx));
            BuilderInstruction p = insns.get(pIdx);
            com.android.tools.smali.dexlib2.builder.instruction.BuilderArrayPayload ap =
                    (com.android.tools.smali.dexlib2.builder.instruction.BuilderArrayPayload) p;
            out.addInstruction(new com.android.tools.smali.dexlib2.builder.instruction.BuilderArrayPayload(
                    ap.getElementWidth(), ap.getArrayElements()));
        }

        // ---- try/catch 重建：对每个 try 区间与其相交的每个块登记一条 catch ----
        for (int[] tr : tryRanges) {
            int sIdx = tr[0], eIdx = tr[1], hIdx = tr[2], typeSlot = tr[3];
            int handlerBlk = blockOfIndex[hIdx];
            // handler 目标：若 handler 块是 move-exception 入口块，指向 moveExc(b)（异常边唯一到达、
            // move-exception 为其首指令）；否则指向 blk(b)。这样 dispatcher 的普通 switch 边不会
            // 落到 move-exception 上，规避 "invalid use of move-exception"。
            Label handler = isHandlerEntry[handlerBlk]
                    ? out.getLabel(moveExc(handlerBlk))
                    : out.getLabel(blk(handlerBlk));
            int idx = sIdx;
            while (idx < eIdx) {
                int b = blockOfIndex[idx];
                int bEnd = blocks.get(b)[1];
                Label from = out.getLabel(blk(b));
                Label to = out.getLabel(blkEnd(b));
                TypeReference type = tryTypes.get(typeSlot);
                if (type != null) {
                    out.addCatch(type, from, to, handler);
                } else {
                    out.addCatch(from, to, handler); // catch-all (finally)
                }
                idx = bEnd; // 跳到下一个块
            }
        }

        return out.getMethodImplementation();
    }

    int getDispatcherRegions() {
        return dispatcherRegions;
    }

    int getReachableAliasCases() {
        return reachableAliasCases;
    }

    /**
     * 发射一条业务语义等价的真实 transition。命中 alias 的目标会根据 rolling route 选择两个
     * 都可执行的 case；两个 case 最终都把状态推进到同一个真实块。
     */
    private static int emitTransition(MethodImplementationBuilder out, int targetBlock,
                                      int stateShareA, int stateShareB, int workReg, int routeReg,
                                      int[] regionOfBlock, int[] stateKey,
                                      boolean[] aliasEnabled, int[] aliasKeyA, int[] aliasKeyB,
                                      int[] encoderTemplate, int[] K1, int[] K2, int[] K3,
                                      long seed, int salt) {
        int region = regionOfBlock[targetBlock];
        if (!aliasEnabled[targetBlock]) {
            emitSplitState(out, stateShareA, stateShareB,
                    enc(stateKey[targetBlock], encoderTemplate[region],
                            K1[region], K2[region], K3[region]), seed, salt);
            out.addInstruction(new BuilderInstruction10t(
                    Opcode.GOTO, out.getLabel(dispatcher(region))));
            return salt + 1;
        }

        long mixed = mix64(seed ^ (0xD6E8FEB86659FD93L * (salt + 1L)));
        int delta = 1 + (int) ((mixed >>> 21) & 0x07ffL);
        out.addInstruction(new BuilderInstruction23x(
                Opcode.XOR_INT, routeReg, routeReg, stateShareA));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.ADD_INT_LIT16, routeReg, routeReg, delta));
        out.addInstruction(new BuilderInstruction22s(
                Opcode.AND_INT_LIT16, workReg, routeReg, 1));
        out.addInstruction(new BuilderInstruction21t(
                Opcode.IF_EQZ, workReg, out.getLabel(routeAlt(salt))));

        emitSplitState(out, stateShareA, stateShareB,
                enc(aliasKeyA[targetBlock], encoderTemplate[region],
                        K1[region], K2[region], K3[region]), seed, salt * 2 + 1);
        out.addInstruction(new BuilderInstruction10t(
                Opcode.GOTO, out.getLabel(dispatcher(region))));

        out.addLabel(routeAlt(salt));
        emitSplitState(out, stateShareA, stateShareB,
                enc(aliasKeyB[targetBlock], encoderTemplate[region],
                        K1[region], K2[region], K3[region]), seed, salt * 2 + 2);
        out.addInstruction(new BuilderInstruction10t(
                Opcode.GOTO, out.getLabel(dispatcher(region))));
        return salt + 1;
    }

    /** 将 encoded 分成两个随机 32 位 XOR share；dispatcher 只在局部 workReg 中短暂合并。 */
    private static void emitSplitState(MethodImplementationBuilder out, int shareA, int shareB,
                                       int encoded, long seed, int salt) {
        long mixed = mix64(seed + 0x9E3779B97F4A7C15L * (salt + 1L));
        int mask = (int) mixed;
        if (mask == 0 || mask == -1) mask ^= 0x6D2B79F5;
        int first = encoded ^ mask;
        if ((mixed & 1L) == 0L) {
            emitIntConst(out, shareA, first);
            emitIntConst(out, shareB, mask);
        } else {
            emitIntConst(out, shareB, mask);
            emitIntConst(out, shareA, first);
        }
    }

    /** 找到移位后参数区中的第一个 int-like 参数，让 alias 选择真正依赖运行时输入。 */
    private static int findIntegralParameterRegister(Method method, int registerCount,
                                                     int parameterRegisterCount) {
        if (method == null || parameterRegisterCount <= 0) return -1;
        int register = registerCount - parameterRegisterCount;
        if ((method.getAccessFlags() & AccessFlags.STATIC.getValue()) == 0) register++; // this
        for (CharSequence parameter : method.getParameterTypes()) {
            String type = parameter == null ? "" : parameter.toString();
            if ("Z".equals(type) || "B".equals(type) || "C".equals(type)
                    || "S".equals(type) || "I".equals(type)) {
                return register;
            }
            register += ("J".equals(type) || "D".equals(type)) ? 2 : 1;
        }
        return -1;
    }

    /** full-int sparse key，排除小整数以避免重新暴露块序号。 */
    private static int nextUniqueKey32(Random random, Set<Integer> used) {
        for (int attempts = 0; attempts < 10000; attempts++) {
            int key = random.nextInt();
            if (key >= -65535 && key <= 65535) continue;
            if (used.add(key)) return key;
        }
        throw new IllegalStateException("unable to allocate unique 32-bit dispatcher key");
    }

    private static void markLeader(boolean[] leader, int idx, int n) {
        if (idx >= 0 && idx <= n) leader[idx] = true;
    }

    /**
     * 后继/跳转目标块号必须落在真实块 [0,k) 内。若 == k（落到尾部数据区）或越界，说明该方法不满足
     * “可执行区以 return/throw/goto 收尾”的前提（异常/畸形），抛出 => 上层安全回退，绝不产出非法 dex。
     */
    private static int requireRealBlock(int blk, int k) {
        if (blk < 0 || blk >= k) {
            throw new IllegalStateException("fall-through/target escapes executable region: " + blk + "/" + k);
        }
        return blk;
    }

    private List<int[]> computeBlocks(MutableMethodImplementation work, boolean[] extraLeader, int execN) {
        List<BuilderInstruction> insns = work.getInstructions();
        int total = insns.size();
        // 只在可执行区 [0, execN) 内切分基本块；尾部 array-data 数据区不参与。
        int n = Math.min(execN, total);
        if (n == 0) return null;
        boolean[] leader = new boolean[n];
        leader[0] = true;
        for (int i = 0; i < n; i++) {
            if (extraLeader != null && i < n && extraLeader[i]) leader[i] = true;
            BuilderInstruction insn = insns.get(i);
            Opcode op = insn.getOpcode();
            if (isGoto(op) || isConditional(op)) {
                if (i + 1 < n) leader[i + 1] = true;
                Integer tgt = branchTargetOrNull(insn);
                if (tgt == null || tgt < 0 || tgt >= n) return null;
                leader[tgt] = true;
            } else if (isReturn(op) || op == Opcode.THROW) {
                if (i + 1 < n) leader[i + 1] = true;
            } else if (op == Opcode.FILL_ARRAY_DATA) {
                // fill-array-data 是“落空”指令：执行后顺序到下一条。目标是尾部 payload（不在 [0,execN)）。
                // 无需为它建块边界；保留在当前块内即可（RegisterShifter 已把它的目标重绑到 payload Label）。
            } else if (isPayloadOrSwitch(op)) {
                // packed/sparse-switch 仍不支持（有位置/对齐/多目标约束）；array-data 已被 execN 排除。
                return null;
            }
        }
        // ---- 强制细分：把顺序执行的长段每隔 splitInterval 切一刀，制造更多基本块 ----
        // 目的：让指令数够但天然块少的方法（如 isRunISOProcess）也能获得足够多的块喂给
        // dispatcher，从而走平坦化而非弱重排。约束：不能把 move-result*/move-exception 作为
        // 块首（它们必须紧跟产出指令），否则 dex 非法。
        if (splitInterval > 0) {
            int since = 0;
            for (int i = 1; i < n; i++) {
                since++;
                if (leader[i]) { since = 0; continue; }
                if (since >= splitInterval && !mustFollowPrev(insns.get(i).getOpcode())) {
                    leader[i] = true;
                    since = 0;
                }
            }
        }
        List<int[]> blocks = new ArrayList<>();
        int s = 0;
        for (int i = 1; i <= n; i++) {
            if (i == n || leader[i]) { blocks.add(new int[]{s, i}); s = i; }
        }
        return blocks;
    }

    /** 这些 opcode 必须紧跟其产出指令，不能作为基本块首（不能在其前切分）。 */
    private static boolean mustFollowPrev(Opcode op) {
        switch (op) {
            case MOVE_RESULT: case MOVE_RESULT_WIDE: case MOVE_RESULT_OBJECT:
            case MOVE_EXCEPTION:
            // fill-array-data 紧跟其 new-array：保持二者同块，使数组引用寄存器在“填充”处
            // 沿块内数据流恒为数组类型，避免被强制切块拆散后在 dispatcher 汇合处发生类型冲突。
            case FILL_ARRAY_DATA:
                return true;
            default:
                return false;
        }
    }

    private static void emitIntConst(MethodImplementationBuilder out, int reg, int value) {
        if (value >= -8 && value <= 7 && reg <= 15) {
            out.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, reg, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            out.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, reg, value));
        } else {
            out.addInstruction(new BuilderInstruction31i(Opcode.CONST, reg, value));
        }
    }

    private static long mix64(long value) {
        value = (value ^ (value >>> 30)) * 0xBF58476D1CE4E5B9L;
        value = (value ^ (value >>> 27)) * 0x94D049BB133111EBL;
        return value ^ (value >>> 31);
    }

    static String templateName(long seed, ObfuscatorConfig config) {
        int template = config.enableMultiTemplate ? (int) ((seed >>> 1) & 7L) : 0;
        String[] encoders = {"add-xor", "xor-add", "add-xor-add", "xor",
                "sub-xor", "xor-sub-xor", "xor-add-xor", "add-xor-sub"};
        String route = ((seed >>> 4) & 1L) == 0L ? "route-add" : "route-xor";
        return "regional-shared-" + route + '-' + encoders[template];
    }

    private static int enc(int id, int template, int K1, int K2, int K3) {
        switch (template) {
            case 1: return (id ^ K1) + K2;
            case 2: return ((id + K2) ^ K1) + K3;
            case 3: return id ^ K1;
            case 4: return (id - K2) ^ K1;
            case 5: return ((id ^ K1) - K2) ^ K3;
            case 6: return ((id ^ K1) + K2) ^ K3;
            case 7: return ((id + K2) ^ K1) - K3;
            default: return (id + K2) ^ K1;
        }
    }

    private static void emitDecode(MethodImplementationBuilder out, int template,
                                   int stateReg, int K1, int K2, int K3) {
        switch (template) {
            case 1:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, -K2));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                break;
            case 2:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, -K3));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, -K2));
                break;
            case 3:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                break;
            case 4:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, K2));
                break;
            case 5:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K3));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, K2));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                break;
            case 6:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K3));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, -K2));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                break;
            case 7:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, K3));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, -K2));
                break;
            default:
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, stateReg, stateReg, K1));
                out.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, stateReg, stateReg, -K2));
        }
    }

    /** 预初始化一个寄存器为 0：reg<=15 用 const/4，否则 const/16。 */
    private static void emitZero(MethodImplementationBuilder out, int reg) {
        if (reg <= 15) {
            out.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, reg, 0));
        } else {
            out.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, reg, 0));
        }
    }

    /** 预初始化一对 wide 寄存器 reg:reg+1 为 0L（const-wide/16，把二者定型为 Long）。 */
    private static void emitZeroWide(MethodImplementationBuilder out, int reg) {
        out.addInstruction(new BuilderInstruction21s(Opcode.CONST_WIDE_16, reg, 0));
    }

    /**
     * 扫描指令，标记“作为 wide（long/double）低半使用”的寄存器。
     * 依据 opcode 名含 WIDE/LONG/DOUBLE，或 CMP_LONG/CMPL_/CMPG_DOUBLE 等——这些指令的
     * wide 操作数寄存器（及其 +1 高半）需要被当作 wide。保守起见：把这些指令涉及的
     * 每个寄存器操作数都按 wide-low 标记（宁可多标，const-wide 覆盖不改变语义）。
     */
    private static boolean[] collectWideLowRegisters(List<BuilderInstruction> insns, int rc) {
        boolean[] wide = new boolean[rc + 2];
        for (BuilderInstruction insn : insns) {
            String name = insn.getOpcode().name;   // 形如 "cmp-long"/"const-wide/16"/"add-double/2addr"
            if (name == null) continue;
            String lower = name.toLowerCase(java.util.Locale.US);
            boolean isWide = lower.contains("wide") || lower.contains("long") || lower.contains("double");
            if (!isWide) continue;
            for (int reg : registersOf(insn)) {
                if (reg >= 0 && reg < rc) { wide[reg] = true; if (reg + 1 < rc) wide[reg + 1] = true; }
            }
        }
        return wide;
    }

    /** 取一条指令的**全部**寄存器操作数（A/B/C，视格式而定），用于 wide 标记。 */
    private static List<Integer> registersOf(BuilderInstruction insn) {
        List<Integer> regs = new ArrayList<>(4);
        if (insn instanceof com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction) {
            regs.add(((com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction) insn).getRegisterA());
        }
        if (insn instanceof com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction) {
            regs.add(((com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction) insn).getRegisterB());
        }
        if (insn instanceof com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction) {
            regs.add(((com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction) insn).getRegisterC());
        }
        // range 调用（3rc）：wide 参数也可能在其中；保守地把整段起始寄存器纳入。
        if (insn instanceof com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction) {
            com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction rr =
                    (com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction) insn;
            int start = rr.getStartRegister();
            for (int i = 0; i < rr.getRegisterCount(); i++) regs.add(start + i);
        }
        return regs;
    }

    private static BuilderInstruction rebuildConditional(BuilderInstruction insn, Label taken) {
        Opcode op = insn.getOpcode();
        if (insn instanceof BuilderInstruction21t) {
            return new BuilderInstruction21t(op, ((Instruction21t) insn).getRegisterA(), taken);
        }
        if (insn instanceof BuilderInstruction22t) {
            Instruction22t t = (Instruction22t) insn;
            return new BuilderInstruction22t(op, t.getRegisterA(), t.getRegisterB(), taken);
        }
        throw new IllegalStateException("not a conditional: " + op);
    }

    private static int targetIndex(BuilderInstruction insn) {
        Integer t = branchTargetOrNull(insn);
        if (t == null) throw new IllegalStateException("unresolved branch target");
        return t;
    }

    private static Integer branchTargetOrNull(BuilderInstruction insn) {
        if (insn instanceof BuilderOffsetInstruction) {
            Label t = ((BuilderOffsetInstruction) insn).getTarget();
            if (t == null || t.getLocation() == null) return null;
            return t.getLocation().getIndex();
        }
        return null;
    }

    private static boolean isGoto(Opcode op) {
        return op == Opcode.GOTO || op == Opcode.GOTO_16 || op == Opcode.GOTO_32;
    }
    private static boolean isConditional(Opcode op) {
        switch (op) {
            case IF_EQ: case IF_NE: case IF_LT: case IF_GE: case IF_GT: case IF_LE:
            case IF_EQZ: case IF_NEZ: case IF_LTZ: case IF_GEZ: case IF_GTZ: case IF_LEZ:
                return true;
            default: return false;
        }
    }
    private static boolean isReturn(Opcode op) {
        switch (op) {
            case RETURN_VOID: case RETURN: case RETURN_WIDE: case RETURN_OBJECT: case RETURN_VOID_NO_BARRIER:
                return true;
            default: return false;
        }
    }
    private static boolean isPayloadOrSwitch(Opcode op) {
        switch (op) {
            case PACKED_SWITCH: case SPARSE_SWITCH:
            case PACKED_SWITCH_PAYLOAD: case SPARSE_SWITCH_PAYLOAD:
            case ARRAY_PAYLOAD: case FILL_ARRAY_DATA:
                return true;
            default: return false;
        }
    }
}
