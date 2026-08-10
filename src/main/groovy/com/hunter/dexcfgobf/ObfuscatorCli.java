package com.hunter.dexcfgobf;

import java.io.File;

/**
 * 命令行入口：对一个目录下的全部 *.dex 就地做控制流混淆。
 * 主要用于本地/CI 手动验证（真实 dex + d8/dexdump），Gradle 集成走
 * {@link DexControlFlowObfuscator#obfuscateDexDirectory(File)}。
 *
 * 用法： java -cp <classpath> com.hunter.dexcfgobf.ObfuscatorCli <dexDir> [includePrefix,...]
 */
public final class ObfuscatorCli {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: ObfuscatorCli <dexDir> [includePrefix,...]");
            System.exit(2);
        }
        File dir = new File(args[0]);
        ObfuscatorConfig config = new ObfuscatorConfig();
        if (args.length >= 2 && !args[1].isEmpty()) {
            config.includePrefixes.clear();
            for (String p : args[1].split(",")) {
                String t = p.trim();
                if (!t.isEmpty()) config.includePrefixes.add(t);
            }
        }
        ObfuscatorStats stats = new DexControlFlowObfuscator(config, ObfuscatorLogger.STDOUT)
                .obfuscateDexDirectory(dir);
        System.out.println("[ObfuscatorCli] " + stats);
        if (stats.dexFailed > 0) {
            System.exit(1);
        }
    }

    private ObfuscatorCli() {}
}
