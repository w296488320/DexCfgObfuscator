package com.zhenxi.hunter.obfuscator;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * DexControlFlowObfuscator
 *
 * 直接基于 smali-dexlib2 对 DEX 做控制流混淆。核心目标：让 jadx / JEB 反编译时
 * 无法还原出线性、可读的控制流，同时绝不改变运行时语义、绝不触发 ART 校验失败。
 *
 * 为什么不沿用 BlackObfuscator：
 *   BlackObfuscator 基于 dex2jar 的 DEX -> IR -> DEX 往返，会重排指令/寄存器，
 *   在方法体变大后频繁触发 "Unsigned short value out of range: 65540"
 *   （分支偏移 / 寄存器号 / 方法引用超出 16 位）并在真机 VerifyError 崩溃。
 *   本实现只在 dexlib2 的指令层做“插桩”，不做整体 IR 往返，天然规避该问题。
 *
 * 设计原则（正确性优先，见 CfgFlattener 的逐条约束）：
 *   1. 只处理白名单包（com.zhenxi 等），硬排除 androidx / kotlin / JNI / 反射 / 序列化。
 *   2. 任何一个不满足安全前提的方法，直接跳过（保持原样），绝不“尽力混淆”。
 *   3. 混淆后若寄存器/指令规模逼近 16 位上限，回退为不混淆。
 */
public final class DexControlFlowObfuscator {

    private final ObfuscatorConfig config;
    private final ObfuscatorLogger logger;

    public DexControlFlowObfuscator(ObfuscatorConfig config, ObfuscatorLogger logger) {
        this.config = config;
        this.logger = logger;
    }

    /**
     * 就地混淆一个目录下的全部 *.dex（AGP 的 R8/mergeDex 产物目录）。
     * @return 统计结果
     */
    public ObfuscatorStats obfuscateDexDirectory(File dexDir) {
        ObfuscatorStats stats = new ObfuscatorStats();
        if (dexDir == null || !dexDir.isDirectory()) {
            logger.warn("obfuscate skip: not a directory -> " + dexDir);
            return stats;
        }
        List<File> dexFiles = new ArrayList<>();
        collectDex(dexDir, dexFiles);
        for (File dexFile : dexFiles) {
            try {
                DexFileObfuscator.obfuscateSingleDex(dexFile, config, logger, stats);
            } catch (Throwable t) {
                // 单个 dex 失败不允许污染其它 dex；记录并保持该 dex 原样。
                logger.warn("obfuscate dex failed, keep original: " + dexFile + " -> " + t);
                stats.dexFailed++;
            }
        }
        logger.info("obfuscate done: " + stats);
        return stats;
    }

    private void collectDex(File dir, List<File> out) {
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                collectDex(child, out);
            } else if (child.isFile() && child.getName().endsWith(".dex")) {
                out.add(child);
            }
        }
    }
}
