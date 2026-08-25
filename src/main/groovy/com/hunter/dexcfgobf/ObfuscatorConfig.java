package com.hunter.dexcfgobf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 混淆配置：控制作用范围与强度。默认值以“正确性/稳定优先”为准。
 */
public final class ObfuscatorConfig {

    /** 需要混淆的类前缀白名单（类描述符形式匹配，如 "com/example"）。 */
    public List<String> includePrefixes = new ArrayList<>();

    /**
     * 硬排除前缀：即便命中 include 也不混淆。
     * 覆盖 Android/Kotlin/Google 通用运行时。业务侧反射、序列化和 JNI 类应通过
     * Gradle 的 blackClass 显式排除，插件本身不绑定任何宿主包名。
     */
    public List<String> excludePrefixes = new ArrayList<>(Arrays.asList(
            "androidx/",
            "android/",
            "kotlin/",
            "kotlinx/",
            "com/google/"
    ));

    /**
     * 混淆深度（对每个可混淆方法插入多少层调度扰动）。BlackObfuscator 的 depth。
     * 保守默认 1；越大越难读，但 dex 越膨胀、越接近上限。
     */
    public int depth = 1;

    /**
     * 方法安全上限：原始寄存器数 + 混淆新增寄存器不得超过该值，
     * 且指令数超过该阈值的方法直接跳过（避免逼近 16 位分支/寄存器上限）。
     */
    public int maxRegisters = 200;
    public int maxInstructions = 1500;

    /**
     * 可复现的每构建种子。实际每方法种子还会混入类名、方法原型和 opcode/CFG 形状，
     * 避免同规模方法生成完全相同的 dispatcher 模板。
     */
    public long seed = 0x5A17C3E2D49B608FL;

    /** 默认支持含 try/catch 的方法；仅显式设为 true 时保守跳过。 */
    public boolean skipMethodsWithTryCatch = false;

    /**
     * 是否移除方法调试信息。
     *
     * <p>默认保留 stack trace 所需的最小行号位置；release + R8 场景中这些是 R8
     * residual line，仍需使用同一次构建的 mapping.txt 才能恢复源码位置。局部变量等
     * 寄存器调试信息不会因该默认值而盲目复制。程序化调用方可显式设为 true 恢复旧的
     * strip 行为，但届时普通 {@code Unknown Source} 崩溃栈无法进行行级还原。</p>
     */
    public boolean stripDebugInfo = false;

    /** 写回前重新解析并执行 DEX 结构验证；失败时整目录回滚。 */
    public boolean verifyStructure = true;

    /** 是否尝试 verifier 类型分析/寄存器类型分离后再进入强平坦化。 */
    public boolean enableRegisterTypeSeparation = true;

    /** 是否允许重定位 array/switch payload。 */
    public boolean enablePayloadRelocation = true;

    /** 是否按方法种子选择不同 dispatcher/编码模板。 */
    public boolean enableMultiTemplate = true;

    /** Gradle adapter 没有匹配 evidence 时拒绝接收带幂等 marker 的旧产物，避免重签配置。 */
    public boolean refuseAlreadyObfuscatedInput;

    /** 覆盖率与体积预算；0 表示不设最低覆盖门槛。 */
    public int minObfuscatedMethods;
    /** 强平坦化方法数下限；reorder 不计入，避免较弱变换填满总覆盖门槛。 */
    public int minFlattenedMethods;
    public double minObfuscatedRatio;
    public double maxSizeIncreasePercent = 100.0d;

    /** JSON 报告开关。报告路径由 Gradle 变体任务决定。 */
    public boolean reportEnabled = true;

    /**
     * R8 后的精确类名白名单（不含开头 L/结尾 ;）。
     * release 在 R8 完成后根据 mapping.txt 从“原类名白名单”解析得到，避免
     * -repackageclasses 把自有类改名后漏混淆，也避免直接放开重打包目录误伤第三方类。
     */
    public final Set<String> resolvedIncludeClasses = new LinkedHashSet<>();
    /** Final owners whose class headers themselves came only from configured business classes. */
    public final Set<String> resolvedClassWideIncludeClasses = new LinkedHashSet<>();
    /**
     * Exact final owner+method-name sites moved/inlined from configured business methods. When an
     * owner is not class-wide, only these names (all residual overloads) may be transformed.
     */
    public final Set<String> resolvedIncludeMethods = new LinkedHashSet<>();
    /** Final generated-decryptor method names that must all be found and transformed. */
    public final Set<String> requiredResolvedIncludeMethods = new LinkedHashSet<>();
    public boolean requireResolvedIncludeClasses;

    public boolean shouldProcessClass(String classDescriptor) {
        // classDescriptor 形如 "Lcom/example/hunter/Foo;"
        String normalized = normalizeClassName(classDescriptor);
        if (hasRequiredMethodOwner(normalized)) return true;
        if (requireResolvedIncludeClasses) {
            return resolvedIncludeClasses.contains(normalized);
        }
        return matchesConfiguredPrefixes(normalized);
    }

    public boolean shouldProcessMethod(String classDescriptor, String methodName) {
        String owner = normalizeClassName(classDescriptor);
        if (methodName != null
                && requiredResolvedIncludeMethods.contains(owner + "->" + methodName)) {
            return true;
        }
        if (!requireResolvedIncludeClasses) {
            return true;
        }
        if (resolvedClassWideIncludeClasses.contains(owner)) {
            return true;
        }
        return methodName != null && resolvedIncludeMethods.contains(owner + "->" + methodName);
    }

    private boolean hasRequiredMethodOwner(String owner) {
        String prefix = owner + "->";
        for (String required : requiredResolvedIncludeMethods) {
            if (required.startsWith(prefix)) return true;
        }
        return false;
    }

    /** R8 mapping 左侧原始类名是否属于配置的业务范围。 */
    public boolean shouldProcessOriginalClass(String originalClassName) {
        return matchesConfiguredPrefixes(normalizeClassName(originalClassName));
    }

    private boolean matchesConfiguredPrefixes(String normalized) {
        for (String ex : excludePrefixes) {
            if (matchesClassOrPackageBoundary(normalized, ex)) {
                return false;
            }
        }
        for (String in : includePrefixes) {
            if (matchesClassOrPackageBoundary(normalized, in)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesClassOrPackageBoundary(String normalized, String rawPrefix) {
        String prefix = normalizeClassName(rawPrefix);
        while (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        if (prefix.isEmpty() || normalized.isEmpty()) return false;
        if (normalized.equals(prefix)) return true;
        if (!normalized.startsWith(prefix) || normalized.length() <= prefix.length()) return false;
        char boundary = normalized.charAt(prefix.length());
        return boundary == '/' || boundary == '$';
    }

    /** 点分/描述符/斜杠类名统一成不带 L; 的斜杠形式。 */
    public static String normalizeClassName(String className) {
        if (className == null) {
            return "";
        }
        String normalized = className.trim().replace('.', '/');
        if (normalized.startsWith("L") && normalized.endsWith(";") && normalized.length() > 2) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return normalized;
    }
}
