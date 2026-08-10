package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;

/**
 * 变换后的方法级安全预算。
 *
 * <p>输入侧的 {@code maxInstructions} 只能避免对本来就很大的方法继续扩张，不能约束
 * dispatcher、trampoline 和 switch payload 的最终体积。这里统一按 DEX code unit 检查输出，
 * 并验证所有短分支仍落在其指令格式的有符号位宽内；失败由调用方回退到更保守的变换。</p>
 */
final class PostTransformBudget {
    private PostTransformBudget() {}

    static Result verify(MethodImplementation before, MethodImplementation after,
                         ObfuscatorConfig config) {
        int beforeUnits = codeUnits(before);
        int afterUnits = codeUnits(after);
        int depth = Math.max(1, config.depth);
        int absoluteLimit = depth <= 1 ? 12_000 : (depth == 2 ? 20_000 : 28_000);
        int minimumAllowance = depth <= 1 ? 4_096 : (depth == 2 ? 8_192 : 12_000);
        int growthFactor = depth <= 1 ? 64 : (depth == 2 ? 128 : 192);
        long relative = Math.max((long) minimumAllowance,
                Math.max(1L, beforeUnits) * growthFactor);
        int allowedUnits = (int) Math.min((long) absoluteLimit, relative);
        if (afterUnits > allowedUnits) {
            throw new IllegalStateException("post-transform code-unit budget exceeded: "
                    + beforeUnits + "->" + afterUnits + " > " + allowedUnits);
        }

        // 重新构造成 mutable 体，让 dexlib2 完成 goto widening 后再检查实际 offset。
        MutableMethodImplementation resolved = new MutableMethodImplementation(after);
        for (Instruction instruction : resolved.getInstructions()) {
            if (!(instruction instanceof OffsetInstruction)) continue;
            Opcode opcode = instruction.getOpcode();
            int offset = ((OffsetInstruction) instruction).getCodeOffset();
            if (opcode == Opcode.GOTO && (offset < Byte.MIN_VALUE || offset > Byte.MAX_VALUE)) {
                throw new IllegalStateException("goto/8 offset overflow after transform: " + offset);
            }
            if ((opcode == Opcode.GOTO_16 || isConditional(opcode))
                    && (offset < Short.MIN_VALUE || offset > Short.MAX_VALUE)) {
                throw new IllegalStateException(opcode + " offset overflow after transform: " + offset);
            }
        }
        return new Result(beforeUnits, afterUnits, allowedUnits);
    }

    static int codeUnits(MethodImplementation implementation) {
        int result = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            result = Math.addExact(result, instruction.getCodeUnits());
        }
        return result;
    }

    private static boolean isConditional(Opcode opcode) {
        switch (opcode) {
            case IF_EQ: case IF_NE: case IF_LT: case IF_GE: case IF_GT: case IF_LE:
            case IF_EQZ: case IF_NEZ: case IF_LTZ: case IF_GEZ: case IF_GTZ: case IF_LEZ:
                return true;
            default:
                return false;
        }
    }

    static final class Result {
        final int beforeCodeUnits;
        final int afterCodeUnits;
        final int allowedCodeUnits;

        Result(int beforeCodeUnits, int afterCodeUnits, int allowedCodeUnits) {
            this.beforeCodeUnits = beforeCodeUnits;
            this.afterCodeUnits = afterCodeUnits;
            this.allowedCodeUnits = allowedCodeUnits;
        }
    }
}
