package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.analysis.AnalyzedInstruction;
import com.android.tools.smali.dexlib2.analysis.ClassPath;
import com.android.tools.smali.dexlib2.analysis.MethodAnalyzer;
import com.android.tools.smali.dexlib2.analysis.RegisterType;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.*;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.*;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;
import com.android.tools.smali.dexlib2.util.MethodUtil;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * verifier 类型分析和保守寄存器类型分离。
 *
 * 只处理没有 try/switch、monitor、未初始化对象和 wide/float 的方法。wide/float 不仅依赖
 * dexlib 数据流类别判断，还会检查 opcode 与引用签名：未解析的外部类方法参数可能令 const
 * 位模式暂时保持 INT，若只信分析结果会在 dispatcher 汇合点制造 INT/FLOAT 冲突。对同一原始 vreg 在互不
 * 相交生命周期中承载的不同引用类型分配独立物理寄存器；若原 CFG 本身存在需要 phi copy 的
 * 类型汇合、range 调用映射不再连续或任一格式无法安全重写，则返回失败并保持原方法。
 */
final class VerifierTypeSeparator {
    static final class Result {
        final MethodImplementation implementation;
        final int addedRegisters;
        final int splitRegisterCount;

        Result(MethodImplementation implementation, int addedRegisters, int splitRegisterCount) {
            this.implementation = implementation;
            this.addedRegisters = addedRegisters;
            this.splitRegisterCount = splitRegisterCount;
        }
    }

    private final ClassPath classPath;
    private final ObfuscatorConfig config;

    VerifierTypeSeparator(ClassPath classPath, ObfuscatorConfig config) {
        this.classPath = classPath;
        this.config = config;
    }

    Result separate(Method method) {
        MethodImplementation implementation = method.getImplementation();
        if (implementation == null || !implementation.getTryBlocks().isEmpty()) return null;
        for (com.android.tools.smali.dexlib2.iface.instruction.Instruction instruction
                : implementation.getInstructions()) {
            Opcode op = instruction.getOpcode();
            if (op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH
                    || op == Opcode.PACKED_SWITCH_PAYLOAD || op == Opcode.SPARSE_SWITCH_PAYLOAD
                    || op == Opcode.MONITOR_ENTER || op == Opcode.MONITOR_EXIT
                    || op == Opcode.NEW_INSTANCE || op == Opcode.CHECK_CAST) {
                return null;
            }
            if (hasUnsupportedPrimitiveSemantics(instruction)) return null;
        }

        MethodAnalyzer analyzer;
        try {
            analyzer = new MethodAnalyzer(classPath, method, null, false);
        } catch (Throwable ignored) {
            return null;
        }
        if (analyzer.getAnalysisException() != null) return null;

        List<AnalyzedInstruction> analyzed = analyzer.getAnalyzedInstructions();
        int registerCount = implementation.getRegisterCount();
        if (registerCount <= 0) return null;
        List<BitSet> liveIn = computeLiveIn(analyzed, registerCount);
        List<LinkedHashSet<String>> families = new ArrayList<>(registerCount);
        for (int r = 0; r < registerCount; r++) families.add(new LinkedHashSet<>());

        for (AnalyzedInstruction instruction : analyzed) {
            if (instruction.isInvokeInit()) return null;
            for (int r = 0; r < registerCount; r++) {
                String pre = family(instruction.getPreInstructionRegisterType(r));
                String post = family(instruction.getPostInstructionRegisterType(r));
                if (isUnsupportedFamily(pre) || isUnsupportedFamily(post)) return null;
                if (isValueFamily(pre)) families.get(r).add(pre);
                if (isValueFamily(post)) families.get(r).add(post);
            }
            if (!hasUnambiguousPredecessorTypes(instruction, registerCount,
                    liveIn.get(instruction.getInstructionIndex()))) return null;
        }

        int added = 0;
        int splitRegisters = 0;
        for (Set<String> set : families) {
            if (set.size() > 1) {
                added += set.size() - 1;
                splitRegisters++;
            }
        }
        if (registerCount + added + 2 > config.maxRegisters) return null;

        int parameterRegisters = MethodUtil.getParameterRegisterCount(method);
        int firstParameter = registerCount - parameterRegisters;
        Map<Integer, Map<String, Integer>> mapping = allocateMappings(
                families, firstParameter, registerCount, added);

        try {
            MethodImplementation separated = rewrite(implementation, analyzed, mapping,
                    registerCount + added, firstParameter, added);
            return new Result(separated, added, splitRegisters);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Map<Integer, Map<String, Integer>> allocateMappings(
            List<LinkedHashSet<String>> families, int firstParameter,
            int oldRegisterCount, int added) {
        Map<Integer, Map<String, Integer>> result = new LinkedHashMap<>();
        int nextExtra = firstParameter;
        for (int r = 0; r < oldRegisterCount; r++) {
            Map<String, Integer> byFamily = new LinkedHashMap<>();
            boolean first = true;
            for (String family : families.get(r)) {
                if (first) {
                    byFamily.put(family, r < firstParameter ? r : r + added);
                    first = false;
                } else {
                    byFamily.put(family, nextExtra++);
                }
            }
            result.put(r, byFamily);
        }
        if (nextExtra != firstParameter + added) {
            throw new IllegalStateException("register allocation mismatch");
        }
        return result;
    }

    private static MethodImplementation rewrite(MethodImplementation implementation,
                                                List<AnalyzedInstruction> analyzed,
                                                Map<Integer, Map<String, Integer>> mapping,
                                                int newRegisterCount,
                                                int firstParameter,
                                                int added) {
        MutableMethodImplementation source = new MutableMethodImplementation(implementation);
        List<BuilderInstruction> instructions = source.getInstructions();
        if (instructions.size() != analyzed.size()) {
            throw new IllegalStateException("analysis/instruction size mismatch");
        }
        MethodImplementationBuilder out = new MethodImplementationBuilder(newRegisterCount);
        for (int i = 0; i < instructions.size(); i++) {
            out.addLabel(RegisterShifter.idxLabel(i));
            out.addInstruction(rebuild(instructions.get(i), analyzed.get(i), mapping,
                    out, firstParameter, added));
        }
        out.addLabel(RegisterShifter.idxLabel(instructions.size()));
        return out.getMethodImplementation();
    }

    private static BuilderInstruction rebuild(BuilderInstruction instruction,
                                              AnalyzedInstruction analyzed,
                                              Map<Integer, Map<String, Integer>> mapping,
                                              MethodImplementationBuilder out,
                                              int firstParameter,
                                              int added) {
        Opcode op = instruction.getOpcode();
        if (instruction instanceof BuilderInstruction10t) {
            return new BuilderInstruction10t(op, target(out, instruction));
        }
        if (instruction instanceof BuilderInstruction20t) {
            return new BuilderInstruction20t(op, target(out, instruction));
        }
        if (instruction instanceof BuilderInstruction30t) {
            return new BuilderInstruction30t(op, target(out, instruction));
        }
        if (instruction instanceof BuilderInstruction21t) {
            Instruction21t t = (Instruction21t) instruction;
            return new BuilderInstruction21t(op, pre(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), target(out, instruction));
        }
        if (instruction instanceof BuilderInstruction22t) {
            Instruction22t t = (Instruction22t) instruction;
            return new BuilderInstruction22t(op,
                    pre(analyzed, t.getRegisterA(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added),
                    target(out, instruction));
        }
        if (instruction instanceof BuilderInstruction10x) return new BuilderInstruction10x(op);
        if (instruction instanceof BuilderInstruction11x) {
            Instruction11x t = (Instruction11x) instruction;
            return new BuilderInstruction11x(op, a(analyzed, op, t.getRegisterA(), mapping,
                    firstParameter, added));
        }
        if (instruction instanceof BuilderInstruction11n) {
            Instruction11n t = (Instruction11n) instruction;
            return new BuilderInstruction11n(op, post(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), t.getNarrowLiteral());
        }
        if (instruction instanceof BuilderInstruction12x) {
            Instruction12x t = (Instruction12x) instruction;
            if (op.name.contains("/2addr")) requireSameFamily(analyzed, t.getRegisterA());
            return new BuilderInstruction12x(op,
                    post(analyzed, t.getRegisterA(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added));
        }
        if (instruction instanceof BuilderInstruction22x) {
            Instruction22x t = (Instruction22x) instruction;
            return new BuilderInstruction22x(op,
                    post(analyzed, t.getRegisterA(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added));
        }
        if (instruction instanceof BuilderInstruction32x) {
            Instruction32x t = (Instruction32x) instruction;
            return new BuilderInstruction32x(op,
                    post(analyzed, t.getRegisterA(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added));
        }
        if (instruction instanceof BuilderInstruction23x) {
            Instruction23x t = (Instruction23x) instruction;
            int ra = op.setsRegister()
                    ? post(analyzed, t.getRegisterA(), mapping, firstParameter, added)
                    : pre(analyzed, t.getRegisterA(), mapping, firstParameter, added);
            return new BuilderInstruction23x(op, ra,
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterC(), mapping, firstParameter, added));
        }
        if (instruction instanceof BuilderInstruction22b) {
            Instruction22b t = (Instruction22b) instruction;
            return new BuilderInstruction22b(op,
                    post(analyzed, t.getRegisterA(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added), t.getNarrowLiteral());
        }
        if (instruction instanceof BuilderInstruction22s) {
            Instruction22s t = (Instruction22s) instruction;
            return new BuilderInstruction22s(op,
                    post(analyzed, t.getRegisterA(), mapping, firstParameter, added),
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added), t.getNarrowLiteral());
        }
        if (instruction instanceof BuilderInstruction21s) {
            Instruction21s t = (Instruction21s) instruction;
            return new BuilderInstruction21s(op, post(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), t.getNarrowLiteral());
        }
        if (instruction instanceof BuilderInstruction21ih) {
            Instruction21ih t = (Instruction21ih) instruction;
            return new BuilderInstruction21ih(op, post(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), t.getNarrowLiteral());
        }
        if (instruction instanceof BuilderInstruction21lh) {
            Instruction21lh t = (Instruction21lh) instruction;
            return new BuilderInstruction21lh(op, post(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), t.getWideLiteral());
        }
        if (instruction instanceof BuilderInstruction31i) {
            Instruction31i t = (Instruction31i) instruction;
            return new BuilderInstruction31i(op, post(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), t.getNarrowLiteral());
        }
        if (instruction instanceof BuilderInstruction31t) {
            Instruction31t t = (Instruction31t) instruction;
            return new BuilderInstruction31t(op, pre(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), target(out, instruction));
        }
        if (instruction instanceof BuilderArrayPayload) {
            BuilderArrayPayload p = (BuilderArrayPayload) instruction;
            return new BuilderArrayPayload(p.getElementWidth(), p.getArrayElements());
        }
        if (instruction instanceof BuilderInstruction51l) {
            Instruction51l t = (Instruction51l) instruction;
            return new BuilderInstruction51l(op, post(analyzed, t.getRegisterA(), mapping,
                    firstParameter, added), t.getWideLiteral());
        }
        if (instruction instanceof BuilderInstruction21c) {
            Instruction21c t = (Instruction21c) instruction;
            return new BuilderInstruction21c(op, a(analyzed, op, t.getRegisterA(), mapping,
                    firstParameter, added), (Reference) t.getReference());
        }
        if (instruction instanceof BuilderInstruction31c) {
            Instruction31c t = (Instruction31c) instruction;
            return new BuilderInstruction31c(op, a(analyzed, op, t.getRegisterA(), mapping,
                    firstParameter, added), (Reference) t.getReference());
        }
        if (instruction instanceof BuilderInstruction22c) {
            Instruction22c t = (Instruction22c) instruction;
            int ra = op.setsRegister()
                    ? post(analyzed, t.getRegisterA(), mapping, firstParameter, added)
                    : pre(analyzed, t.getRegisterA(), mapping, firstParameter, added);
            return new BuilderInstruction22c(op, ra,
                    pre(analyzed, t.getRegisterB(), mapping, firstParameter, added),
                    (Reference) t.getReference());
        }
        if (instruction instanceof BuilderInstruction35c) {
            Instruction35c t = (Instruction35c) instruction;
            int count = t.getRegisterCount();
            return new BuilderInstruction35c(op, count,
                    count > 0 ? pre(analyzed, t.getRegisterC(), mapping, firstParameter, added) : 0,
                    count > 1 ? pre(analyzed, t.getRegisterD(), mapping, firstParameter, added) : 0,
                    count > 2 ? pre(analyzed, t.getRegisterE(), mapping, firstParameter, added) : 0,
                    count > 3 ? pre(analyzed, t.getRegisterF(), mapping, firstParameter, added) : 0,
                    count > 4 ? pre(analyzed, t.getRegisterG(), mapping, firstParameter, added) : 0,
                    (Reference) t.getReference());
        }
        if (instruction instanceof BuilderInstruction3rc) {
            Instruction3rc t = (Instruction3rc) instruction;
            int start = pre(analyzed, t.getStartRegister(), mapping, firstParameter, added);
            for (int i = 1; i < t.getRegisterCount(); i++) {
                int mapped = pre(analyzed, t.getStartRegister() + i, mapping, firstParameter, added);
                if (mapped != start + i) throw new IllegalStateException("range invoke lost contiguity");
            }
            return new BuilderInstruction3rc(op, start, t.getRegisterCount(), (Reference) t.getReference());
        }
        throw new UnsupportedOperationException("unsupported typed rewrite: " + instruction.getClass());
    }

    private static int a(AnalyzedInstruction instruction, Opcode opcode, int register,
                         Map<Integer, Map<String, Integer>> mapping,
                         int firstParameter, int added) {
        return opcode.setsRegister()
                ? post(instruction, register, mapping, firstParameter, added)
                : pre(instruction, register, mapping, firstParameter, added);
    }

    private static int pre(AnalyzedInstruction instruction, int register,
                           Map<Integer, Map<String, Integer>> mapping,
                           int firstParameter, int added) {
        return mapped(register, family(instruction.getPreInstructionRegisterType(register)),
                mapping, firstParameter, added);
    }

    private static int post(AnalyzedInstruction instruction, int register,
                            Map<Integer, Map<String, Integer>> mapping,
                            int firstParameter, int added) {
        return mapped(register, family(instruction.getPostInstructionRegisterType(register)),
                mapping, firstParameter, added);
    }

    private static int mapped(int register, String family,
                              Map<Integer, Map<String, Integer>> mapping,
                              int firstParameter, int added) {
        Integer value = mapping.get(register).get(family);
        if (value != null) return value;
        if (!isValueFamily(family)) return register < firstParameter ? register : register + added;
        throw new IllegalStateException("no register mapping for v" + register + "/" + family);
    }

    private static Label target(MethodImplementationBuilder out, BuilderInstruction instruction) {
        com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction offset =
                (com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction) instruction;
        if (offset.getTarget() == null || offset.getTarget().getLocation() == null) {
            throw new IllegalStateException("unresolved target");
        }
        return out.getLabel(RegisterShifter.idxLabel(offset.getTarget().getLocation().getIndex()));
    }

    private static void requireSameFamily(AnalyzedInstruction instruction, int register) {
        String pre = family(instruction.getPreInstructionRegisterType(register));
        String post = family(instruction.getPostInstructionRegisterType(register));
        if (!pre.equals(post)) throw new IllegalStateException("read/write register changes verifier family");
    }

    private static boolean hasUnambiguousPredecessorTypes(AnalyzedInstruction instruction,
                                                           int registerCount, BitSet liveIn) {
        if (instruction.getPredecessorCount() <= 1) return true;
        for (int r = liveIn.nextSetBit(0); r >= 0 && r < registerCount;
             r = liveIn.nextSetBit(r + 1)) {
            String seen = null;
            for (AnalyzedInstruction predecessor : instruction.getPredecessors()) {
                String current = family(instruction.getPredecessorRegisterType(predecessor, r));
                if (!isValueFamily(current)) continue;
                if (seen == null) seen = current;
                else if (!seen.equals(current)) return false;
            }
        }
        return true;
    }

    /** 标准反向活跃性分析：只有 join 后仍会被读取的寄存器才需要 phi/边复制。 */
    private static List<BitSet> computeLiveIn(List<AnalyzedInstruction> instructions,
                                               int registerCount) {
        int n = instructions.size();
        List<BitSet> uses = new ArrayList<>(n);
        List<BitSet> defs = new ArrayList<>(n);
        List<BitSet> liveIn = new ArrayList<>(n);
        List<BitSet> liveOut = new ArrayList<>(n);
        for (AnalyzedInstruction analyzed : instructions) {
            BitSet use = usedRegisters(analyzed, registerCount);
            BitSet def = new BitSet(registerCount);
            for (int register : analyzed.getSetRegisters()) {
                if (register >= 0 && register < registerCount) def.set(register);
            }
            uses.add(use);
            defs.add(def);
            liveIn.add(new BitSet(registerCount));
            liveOut.add(new BitSet(registerCount));
        }
        boolean changed;
        do {
            changed = false;
            for (int i = n - 1; i >= 0; i--) {
                BitSet out = new BitSet(registerCount);
                for (AnalyzedInstruction successor : instructions.get(i).getSuccessors()) {
                    int index = successor.getInstructionIndex();
                    if (index >= 0 && index < n) out.or(liveIn.get(index));
                }
                BitSet in = (BitSet) out.clone();
                in.andNot(defs.get(i));
                in.or(uses.get(i));
                if (!out.equals(liveOut.get(i)) || !in.equals(liveIn.get(i))) {
                    liveOut.set(i, out);
                    liveIn.set(i, in);
                    changed = true;
                }
            }
        } while (changed);
        return liveIn;
    }

    private static BitSet usedRegisters(AnalyzedInstruction analyzed, int registerCount) {
        com.android.tools.smali.dexlib2.iface.instruction.Instruction instruction =
                analyzed.getInstruction();
        Opcode opcode = instruction.getOpcode();
        BitSet result = new BitSet(registerCount);
        if (instruction instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction range = (RegisterRangeInstruction) instruction;
            result.set(range.getStartRegister(), range.getStartRegister() + range.getRegisterCount());
            return result;
        }
        if (instruction instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction five = (FiveRegisterInstruction) instruction;
            int count = five.getRegisterCount();
            int[] values = {five.getRegisterC(), five.getRegisterD(), five.getRegisterE(),
                    five.getRegisterF(), five.getRegisterG()};
            for (int i = 0; i < count; i++) result.set(values[i]);
            return result;
        }
        if (instruction instanceof OneRegisterInstruction) {
            int a = ((OneRegisterInstruction) instruction).getRegisterA();
            if (!opcode.setsRegister()) result.set(a);
        }
        if (instruction instanceof TwoRegisterInstruction) {
            TwoRegisterInstruction two = (TwoRegisterInstruction) instruction;
            result.set(two.getRegisterB());
            if (!opcode.setsRegister() || opcode.name.contains("/2addr")) result.set(two.getRegisterA());
        }
        if (instruction instanceof ThreeRegisterInstruction) {
            ThreeRegisterInstruction three = (ThreeRegisterInstruction) instruction;
            result.set(three.getRegisterB());
            result.set(three.getRegisterC());
            if (!opcode.setsRegister()) result.set(three.getRegisterA());
        }
        return result;
    }

    private static String family(RegisterType type) {
        if (type == null) return "UNKNOWN";
        switch (type.category) {
            case RegisterType.UNKNOWN: return "UNKNOWN";
            case RegisterType.UNINIT: return "UNINIT";
            case RegisterType.CONFLICTED: return "CONFLICT";
            case RegisterType.FLOAT: return "FLOAT";
            case RegisterType.LONG_LO: case RegisterType.LONG_HI: return "LONG";
            case RegisterType.DOUBLE_LO: case RegisterType.DOUBLE_HI: return "DOUBLE";
            case RegisterType.UNINIT_REF: case RegisterType.UNINIT_THIS: return "UNINIT_REF";
            case RegisterType.REFERENCE:
                return "REF:" + (type.type == null ? "?" : type.type.getType());
            case RegisterType.NULL: return "ZERO";
            default: return "INT";
        }
    }

    private static boolean isUnsupportedFamily(String family) {
        return "CONFLICT".equals(family) || "FLOAT".equals(family)
                || "LONG".equals(family) || "DOUBLE".equals(family)
                || "UNINIT_REF".equals(family);
    }

    private static boolean isValueFamily(String family) {
        return family != null && !"UNKNOWN".equals(family) && !"UNINIT".equals(family);
    }

    /**
     * MethodAnalyzer 在 classpath 不完整时仍可能完成分析，但不会总能把 const 位模式提升为
     * FLOAT/DOUBLE/LONG。这里根据 DEX 指令语义和引用描述符做保守兜底，避免把这些值带入
     * 新增的 dispatcher CFG 汇合点。
     */
    private static boolean hasUnsupportedPrimitiveSemantics(
            com.android.tools.smali.dexlib2.iface.instruction.Instruction instruction) {
        String opcodeName = instruction.getOpcode().name;
        if (opcodeName.contains("float") || opcodeName.contains("double")
                || opcodeName.contains("long") || opcodeName.contains("wide")
                || opcodeName.contains("boolean") || opcodeName.contains("byte")
                || opcodeName.contains("char") || opcodeName.contains("short")) {
            return true;
        }
        if (!(instruction instanceof ReferenceInstruction)) return false;
        Reference reference = ((ReferenceInstruction) instruction).getReference();
        if (reference instanceof FieldReference) {
            return isUnsupportedScalarDescriptor(((FieldReference) reference).getType());
        }
        if (reference instanceof TypeReference) {
            // 数组本身属于引用类型；但 [F/[D/[J 的 payload/use 仍涉及 wide/float 位宽。
            return isWideOrFloatDescriptor(((TypeReference) reference).getType());
        }
        if (reference instanceof MethodReference) {
            MethodReference method = (MethodReference) reference;
            if (isUnsupportedScalarDescriptor(method.getReturnType())) return true;
            for (CharSequence parameter : method.getParameterTypes()) {
                if (isUnsupportedScalarDescriptor(parameter)) return true;
            }
        }
        return false;
    }

    private static boolean isWideOrFloatDescriptor(CharSequence descriptor) {
        if (descriptor == null) return false;
        String value = descriptor.toString();
        int index = 0;
        while (index < value.length() && value.charAt(index) == '[') index++;
        if (index >= value.length()) return false;
        char type = value.charAt(index);
        return type == 'F' || type == 'D' || type == 'J';
    }

    private static boolean isUnsupportedScalarDescriptor(CharSequence descriptor) {
        if (descriptor == null) return false;
        String value = descriptor.toString();
        // 数组在 verifier 中是引用；元素的窄类型由 aget/aput-* opcode 单独识别。
        if (value.startsWith("[")) return isWideOrFloatDescriptor(value);
        if (value.length() != 1) return false;
        char type = value.charAt(0);
        return type == 'Z' || type == 'B' || type == 'S' || type == 'C'
                || type == 'F' || type == 'D' || type == 'J';
    }
}
