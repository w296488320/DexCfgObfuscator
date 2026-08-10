package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.*;
import com.android.tools.smali.dexlib2.iface.instruction.formats.*;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * RegisterShifter —— 把一个方法体的**所有寄存器引用整体 +delta**，寄存器总数也 +delta。
 *
 * 为什么要整体平移：控制流平坦化需要一个额外的 state 寄存器。DEX 的参数寄存器固定在
 * “最高的若干个”位置，若把新寄存器加在末尾会打乱参数映射。把 state 放在 v0、其余寄存器
 * 统一 +1，则原来的局部与参数**同步上移一格**，参数依旧落在最高位，映射不变。
 *
 * 正确性保证：
 *   - 逐条按指令格式重建，寄存器操作数 +delta；非寄存器指令原样保留（但分支用新 Label 重连）。
 *   - 4 位（nibble）寄存器字段一旦 +delta 超过 v15，dexlib2 构造器会抛异常；
 *     本类不吞异常，交由上层 flatten 的 try/catch 回退为“不混淆”，绝不产出非法 dex。
 *   - 不支持就地重排：全程用 MethodImplementationBuilder + 具名 Label 重新发射，
 *     分支目标按“原指令索引”命名，dexlib2 自动重算偏移、自动升格 goto。
 *
 * 不支持的格式（遇到即抛，方法回退不混淆）：
 *   - 3rc/3rms/3rmi/4rcc（range 调用，起始寄存器 +delta 可能破坏连续区间语义之外的约束）；
 *   - 35c/35mi/35ms（5 寄存器打包，nibble 编码，风险高）；
 *   - switch/array payload 会按原目标索引重绑到新 Label；不复制旧实现上的 Label。
 * 说明：这些一旦出现就整段放弃，确保“要么正确混淆、要么原样”。
 */
final class RegisterShifter {

    /** 平移结果：新指令已写入 builder；返回“原指令索引 -> 该指令在新体中的具名 Label 名”。 */
    static final class Result {
        final MethodImplementationBuilder builder;
        final int newRegisterCount;
        Result(MethodImplementationBuilder b, int rc) { this.builder = b; this.newRegisterCount = rc; }
    }

    /** 分支目标 Label 名：以“原始指令索引”为键，保证 shift 前后目标一致。 */
    static String idxLabel(int originalIndex) { return "S" + originalIndex; }

    /**
     * 把 src 的所有寄存器 +delta，重新发射到一个新的 MethodImplementationBuilder。
     * @throws RuntimeException 遇到 nibble 溢出或不支持的格式（上层据此回退）。
     */
    static Result shift(MutableMethodImplementation src, int delta) {
        List<BuilderInstruction> insns = src.getInstructions();
        int n = insns.size();
        int newRc = src.getRegisterCount() + delta;

        MethodImplementationBuilder out = new MethodImplementationBuilder(newRc);

        // 预先记录每条原指令的分支目标索引（若是分支）。
        for (int i = 0; i < n; i++) {
            BuilderInstruction insn = insns.get(i);
            // 每条指令前放一个以原索引命名的 Label，供分支/ dispatcher 引用。
            out.addLabel(idxLabel(i));
            out.addInstruction(rebuildShifted(insn, delta, out));
        }
        // 末尾 Label（供“落空到方法末尾”之类的目标，一般不会被用到）。
        out.addLabel(idxLabel(n));

        // 不能只平移指令：try/catch 表也是 MethodImplementation 的语义组成部分。
        // 所有边界都按“原指令索引”重新绑定到新实现的 S# Label；否则 flatten 会看到
        // 空异常表，最终 DEX 虽可写出，但异常路径会静默丢失、改变原 App 逻辑。
        List<? extends TryBlock<? extends ExceptionHandler>> tries = src.getTryBlocks();
        if (tries != null) {
            for (TryBlock<? extends ExceptionHandler> tb : tries) {
                com.android.tools.smali.dexlib2.builder.BuilderTryBlock btb =
                        (com.android.tools.smali.dexlib2.builder.BuilderTryBlock) tb;
                int start = btb.start.getLocation().getIndex();
                int end = btb.end.getLocation().getIndex();
                if (start < 0 || end > n || start >= end) {
                    throw new IllegalStateException("bad try range during shift: " + start + ".." + end);
                }
                for (ExceptionHandler handler : tb.getExceptionHandlers()) {
                    com.android.tools.smali.dexlib2.builder.BuilderExceptionHandler beh =
                            (com.android.tools.smali.dexlib2.builder.BuilderExceptionHandler) handler;
                    int handlerIndex = beh.getHandler().getLocation().getIndex();
                    if (handlerIndex < 0 || handlerIndex >= n) {
                        throw new IllegalStateException("bad handler during shift: " + handlerIndex);
                    }
                    TypeReference type = handler.getExceptionTypeReference();
                    Label from = out.getLabel(idxLabel(start));
                    Label to = out.getLabel(idxLabel(end));
                    Label target = out.getLabel(idxLabel(handlerIndex));
                    if (type != null) out.addCatch(type, from, to, target);
                    else out.addCatch(from, to, target);
                }
            }
        }

        return new Result(out, newRc);
    }

    /** 依格式重建单条指令：寄存器 +delta；分支改用 out 上以原目标索引命名的 Label。 */
    private static BuilderInstruction rebuildShifted(BuilderInstruction insn, int d,
                                                     MethodImplementationBuilder out) {
        Opcode op = insn.getOpcode();
        // ---- 分支（offset）指令：目标索引从原 Label 读出，改绑新 Label ----
        if (insn instanceof BuilderInstruction10t) {
            return new BuilderInstruction10t(op, out.getLabel(idxLabel(targetIdx(insn))));
        }
        if (insn instanceof BuilderInstruction20t) {
            return new BuilderInstruction20t(op, out.getLabel(idxLabel(targetIdx(insn))));
        }
        if (insn instanceof BuilderInstruction30t) {
            return new BuilderInstruction30t(op, out.getLabel(idxLabel(targetIdx(insn))));
        }
        if (insn instanceof BuilderInstruction21t) {
            return new BuilderInstruction21t(op, r(((Instruction21t) insn).getRegisterA(), d),
                    out.getLabel(idxLabel(targetIdx(insn))));
        }
        if (insn instanceof BuilderInstruction22t) {
            Instruction22t t = (Instruction22t) insn;
            return new BuilderInstruction22t(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d),
                    out.getLabel(idxLabel(targetIdx(insn))));
        }
        // ---- 普通寄存器指令：按格式 +d ----
        if (insn instanceof BuilderInstruction10x) {
            return new BuilderInstruction10x(op);
        }
        if (insn instanceof BuilderInstruction11x) {
            return new BuilderInstruction11x(op, r(((Instruction11x) insn).getRegisterA(), d));
        }
        if (insn instanceof BuilderInstruction11n) {
            Instruction11n t = (Instruction11n) insn;
            int a = r(t.getRegisterA(), d);
            // const/4 的目标只有 4 bit；整体平移越过 v15 时可无损升级为 const/16。
            if (op == Opcode.CONST_4 && a > 15) {
                return new BuilderInstruction21s(Opcode.CONST_16, a, t.getNarrowLiteral());
            }
            return new BuilderInstruction11n(op, a, t.getNarrowLiteral());
        }
        if (insn instanceof BuilderInstruction12x) {
            Instruction12x t = (Instruction12x) insn;
            int a = r(t.getRegisterA(), d);
            int b = r(t.getRegisterB(), d);
            if (a > 15 || b > 15) {
                // 三种 move 都有 22x 的 /from16 等价形式；其它 12x（2addr/unary）没有通用
                // 无副作用升级，仍由上层安全回退。
                if (op == Opcode.MOVE) return new BuilderInstruction22x(Opcode.MOVE_FROM16, a, b);
                if (op == Opcode.MOVE_WIDE) return new BuilderInstruction22x(Opcode.MOVE_WIDE_FROM16, a, b);
                if (op == Opcode.MOVE_OBJECT) return new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, a, b);
            }
            return new BuilderInstruction12x(op, a, b);
        }
        if (insn instanceof BuilderInstruction22x) {
            Instruction22x t = (Instruction22x) insn;
            return new BuilderInstruction22x(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d));
        }
        if (insn instanceof BuilderInstruction32x) {
            Instruction32x t = (Instruction32x) insn;
            return new BuilderInstruction32x(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d));
        }
        if (insn instanceof BuilderInstruction23x) {
            Instruction23x t = (Instruction23x) insn;
            return new BuilderInstruction23x(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d), r(t.getRegisterC(), d));
        }
        if (insn instanceof BuilderInstruction22b) {
            Instruction22b t = (Instruction22b) insn;
            return new BuilderInstruction22b(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d), t.getNarrowLiteral());
        }
        if (insn instanceof BuilderInstruction22s) {
            Instruction22s t = (Instruction22s) insn;
            return new BuilderInstruction22s(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d), t.getNarrowLiteral());
        }
        if (insn instanceof BuilderInstruction21s) {
            Instruction21s t = (Instruction21s) insn;
            return new BuilderInstruction21s(op, r(t.getRegisterA(), d), t.getNarrowLiteral());
        }
        if (insn instanceof BuilderInstruction21ih) {
            Instruction21ih t = (Instruction21ih) insn;
            return new BuilderInstruction21ih(op, r(t.getRegisterA(), d), t.getNarrowLiteral());
        }
        if (insn instanceof BuilderInstruction21lh) {
            Instruction21lh t = (Instruction21lh) insn;
            return new BuilderInstruction21lh(op, r(t.getRegisterA(), d), t.getWideLiteral());
        }
        if (insn instanceof BuilderInstruction31i) {
            Instruction31i t = (Instruction31i) insn;
            return new BuilderInstruction31i(op, r(t.getRegisterA(), d), t.getNarrowLiteral());
        }
        // fill-array-data / packed-switch / sparse-switch（31t）：像分支一样是 offset 指令，
        // 目标是尾部 payload。寄存器平移，payload 目标按原索引重绑。
        // 寄存器 +d（持有数组引用），目标改绑到 payload 的原索引 Label（payload 由下面 BuilderArrayPayload 分支重发）。
        if (insn instanceof BuilderInstruction31t) {
            Instruction31t t = (Instruction31t) insn;
            return new BuilderInstruction31t(op, r(t.getRegisterA(), d),
                    out.getLabel(idxLabel(targetIdx(insn))));
        }
        // switch payload：key 不变；每个 case 目标按原指令索引重绑。
        if (insn instanceof BuilderPackedSwitchPayload) {
            List<? extends BuilderSwitchElement> old =
                    ((BuilderPackedSwitchPayload) insn).getSwitchElements();
            if (old.isEmpty()) return new BuilderPackedSwitchPayload(0, new ArrayList<Label>());
            List<Label> targets = new ArrayList<>(old.size());
            for (BuilderSwitchElement element : old) {
                targets.add(out.getLabel(idxLabel(element.getTarget().getLocation().getIndex())));
            }
            return new BuilderPackedSwitchPayload(old.get(0).getKey(), targets);
        }
        if (insn instanceof BuilderSparseSwitchPayload) {
            List<com.android.tools.smali.dexlib2.builder.SwitchLabelElement> elements = new ArrayList<>();
            for (BuilderSwitchElement element :
                    ((BuilderSparseSwitchPayload) insn).getSwitchElements()) {
                elements.add(new com.android.tools.smali.dexlib2.builder.SwitchLabelElement(
                        element.getKey(),
                        out.getLabel(idxLabel(element.getTarget().getLocation().getIndex()))));
            }
            return new BuilderSparseSwitchPayload(elements);
        }
        // array-data payload：纯数据，无寄存器；原样重建（元素与元素宽度不变）。
        if (insn instanceof BuilderArrayPayload) {
            BuilderArrayPayload p = (BuilderArrayPayload) insn;
            return new BuilderArrayPayload(p.getElementWidth(), p.getArrayElements());
        }
        if (insn instanceof BuilderInstruction51l) {
            Instruction51l t = (Instruction51l) insn;
            return new BuilderInstruction51l(op, r(t.getRegisterA(), d), t.getWideLiteral());
        }
        if (insn instanceof BuilderInstruction21c) {
            Instruction21c t = (Instruction21c) insn;
            return new BuilderInstruction21c(op, r(t.getRegisterA(), d), (Reference) t.getReference());
        }
        if (insn instanceof BuilderInstruction31c) {
            Instruction31c t = (Instruction31c) insn;
            return new BuilderInstruction31c(op, r(t.getRegisterA(), d), (Reference) t.getReference());
        }
        if (insn instanceof BuilderInstruction22c) {
            Instruction22c t = (Instruction22c) insn;
            return new BuilderInstruction22c(op, r(t.getRegisterA(), d), r(t.getRegisterB(), d), (Reference) t.getReference());
        }
        if (insn instanceof BuilderInstruction35c) {
            Instruction35c t = (Instruction35c) insn;
            int c = t.getRegisterCount();
            return new BuilderInstruction35c(op, c,
                    c > 0 ? r(t.getRegisterC(), d) : 0,
                    c > 1 ? r(t.getRegisterD(), d) : 0,
                    c > 2 ? r(t.getRegisterE(), d) : 0,
                    c > 3 ? r(t.getRegisterF(), d) : 0,
                    c > 4 ? r(t.getRegisterG(), d) : 0,
                    (Reference) t.getReference());
        }
        if (insn instanceof BuilderInstruction3rc) {
            Instruction3rc t = (Instruction3rc) insn;
            return new BuilderInstruction3rc(op, r(t.getStartRegister(), d), t.getRegisterCount(), (Reference) t.getReference());
        }
        // 其它格式（35mi/35ms/3rmi/3rms/45cc/4rcc/20bc/22cs 等）不常见于应用类，
        // 直接放弃以保安全。
        throw new UnsupportedOperationException("unsupported format for shift: " + op + " / " + insn.getClass().getSimpleName());
    }

    /** 寄存器 +delta，负数或异常交由上层。 */
    private static int r(int reg, int delta) {
        return reg + delta;
    }

    /** 读取分支指令的目标“原指令索引”（shift 前的索引，用作 Label 名）。 */
    private static int targetIdx(BuilderInstruction insn) {
        com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction off =
                (com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction) insn;
        Label tgt = off.getTarget();
        if (tgt == null || tgt.getLocation() == null) {
            throw new IllegalStateException("unresolved branch target during shift");
        }
        return tgt.getLocation().getIndex();
    }

    private RegisterShifter() {}
}
