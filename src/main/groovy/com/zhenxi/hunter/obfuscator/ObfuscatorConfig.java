package com.zhenxi.hunter.obfuscator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 混淆配置：控制作用范围与强度。默认值以“正确性/稳定优先”为准。
 */
public final class ObfuscatorConfig {

    /** 需要混淆的类前缀白名单（类描述符形式匹配，如 "com/zhenxi"）。 */
    public List<String> includePrefixes = new ArrayList<>(Arrays.asList(
            "com/zhenxi",
            "zhenxi233",
            "YouAreLoser"
    ));

    /**
     * 硬排除前缀：即便命中 include 也不混淆。
     * 覆盖第三方库、Kotlin 运行时、以及会被反射/序列化/JNI 调用的类。
     */
    public List<String> excludePrefixes = new ArrayList<>(Arrays.asList(
            "androidx/",
            "android/",
            "kotlin/",
            "kotlinx/",
            "com/google/",
            "com/zhenxi/hunter/stringfog/",   // stringfog 运行时实现，勿动
            "com/zhenxi/hunter/NativeEngine"  // JNI 注册类，方法签名/入口必须稳定
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

    /** 第一版稳定策略：跳过含 try/catch 的方法。true=跳过。 */
    public boolean skipMethodsWithTryCatch = true;

    /** 是否移除调试行号信息（.line / .local），进一步妨碍反编译定位。 */
    public boolean stripDebugInfo = true;

    public boolean shouldProcessClass(String classDescriptor) {
        // classDescriptor 形如 "Lcom/zhenxi/hunter/Foo;"
        String normalized = classDescriptor;
        if (normalized.startsWith("L") && normalized.endsWith(";")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
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
}
