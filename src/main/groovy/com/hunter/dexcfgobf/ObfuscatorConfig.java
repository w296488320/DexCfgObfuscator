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

    /** 是否移除调试行号信息（.line / .local），进一步妨碍反编译定位。 */
    public boolean stripDebugInfo = true;

    /** 写回前重新解析并执行 DEX 结构验证；失败时整目录回滚。 */
    public boolean verifyStructure = true;

    /** 是否尝试 verifier 类型分析/寄存器类型分离后再进入强平坦化。 */
    public boolean enableRegisterTypeSeparation = true;

    /** 是否允许重定位 array/switch payload。 */
    public boolean enablePayloadRelocation = true;

    /** 是否按方法种子选择不同 dispatcher/编码模板。 */
    public boolean enableMultiTemplate = true;

    /** 覆盖率与体积预算；0 表示不设最低覆盖门槛。 */
    public int minObfuscatedMethods;
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
    public boolean requireResolvedIncludeClasses;

    public boolean shouldProcessClass(String classDescriptor) {
        // classDescriptor 形如 "Lcom/example/hunter/Foo;"
        String normalized = normalizeClassName(classDescriptor);
        if (requireResolvedIncludeClasses) {
            return resolvedIncludeClasses.contains(normalized);
        }
        return matchesConfiguredPrefixes(normalized);
    }

    /** R8 mapping 左侧原始类名是否属于配置的业务范围。 */
    public boolean shouldProcessOriginalClass(String originalClassName) {
        return matchesConfiguredPrefixes(normalizeClassName(originalClassName));
    }

    private boolean matchesConfiguredPrefixes(String normalized) {
        for (String ex : excludePrefixes) {
            if (normalized.startsWith(ex)) {
                return false;
            }
        }
        for (String in : includePrefixes) {
            if (normalized.startsWith(in)) {
                return true;
            }
        }
        return false;
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
