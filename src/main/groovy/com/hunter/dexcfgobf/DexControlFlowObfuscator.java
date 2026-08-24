package com.hunter.dexcfgobf;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
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
 *   1. 只处理显式配置的白名单包，硬排除 Android / Kotlin / Google 通用运行时。
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
        dexFiles.sort(Comparator.comparing(File::getAbsolutePath));
        if (dexFiles.isEmpty()) {
            logger.info("obfuscate skip: no dex under " + dexDir);
            return stats;
        }

        // 先在目录外的 staging 副本上完成全部 DEX 变换。任一 DEX 失败时，原 producer
        // 输出完全不动，避免下次 Gradle 重跑面对“半混淆”目录。
        Path staging = null;
        Path backup = null;
        List<Path[]> pairs = new ArrayList<>(); // {source, staged}
        try {
            Path parent = dexDir.toPath().toAbsolutePath().getParent();
            if (parent == null) throw new IOException("dex dir has no parent: " + dexDir);
            staging = Files.createTempDirectory(parent, ".dexcfgobf-staging-");
            for (File dexFile : dexFiles) {
                Path source = dexFile.toPath().toAbsolutePath();
                Path relative = dexDir.toPath().toAbsolutePath().relativize(source);
                Path staged = staging.resolve(relative);
                Files.createDirectories(staged.getParent());
                Files.copy(source, staged, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.COPY_ATTRIBUTES);
                DexFileObfuscator.obfuscateSingleDex(staged.toFile(), config, logger, stats);
                pairs.add(new Path[]{source, staged});
            }

            if (config.refuseAlreadyObfuscatedInput
                    && stats.methodsSkippedAlreadyObfuscated > 0) {
                throw new IllegalStateException("input contains "
                        + stats.methodsSkippedAlreadyObfuscated
                        + " already-obfuscated method marker(s) without matching build evidence");
            }
            // 只提交内容实际变化的 DEX；已平坦化方法含 switch，会保持幂等、不反复放大。
            List<Path[]> changed = new ArrayList<>();
            for (Path[] pair : pairs) {
                if (Files.mismatch(pair[0], pair[1]) != -1L) changed.add(pair);
            }
            if (!changed.isEmpty()) {
                backup = Files.createTempDirectory(parent, ".dexcfgobf-backup-");
                for (int i = 0; i < changed.size(); i++) {
                    Path saved = backup.resolve(Integer.toString(i) + ".dex");
                    Files.copy(changed.get(i)[0], saved, StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.COPY_ATTRIBUTES);
                }
                try {
                    for (Path[] pair : changed) replaceFile(pair[1], pair[0]);
                } catch (Exception commitFailure) {
                    // commit 中途失败也恢复全部原文件；恢复失败会作为 suppressed 暴露并让构建失败。
                    for (int i = 0; i < changed.size(); i++) {
                        try {
                            Files.copy(backup.resolve(Integer.toString(i) + ".dex"), changed.get(i)[0],
                                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
                        } catch (Exception restoreFailure) {
                            commitFailure.addSuppressed(restoreFailure);
                        }
                    }
                    throw commitFailure;
                }
            }
        } catch (Exception failure) {
            logger.warn("obfuscate directory failed, original dex restored/kept: " + dexDir + " -> " + failure);
            stats.dexFailed++;
        } finally {
            deleteTree(staging);
            deleteTree(backup);
        }
        logger.info("obfuscate done: " + stats);
        return stats;
    }

    private static void replaceFile(Path staged, Path target) throws IOException {
        try {
            Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
            Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteTree(Path root) {
        if (root == null || !Files.exists(root)) return;
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); }
                catch (IOException ignored) { /* 构建临时目录，清理失败不覆盖主异常。 */ }
            });
        } catch (IOException ignored) {
            // 同上：不让清理错误掩盖真正的 DEX 变换结果。
        }
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
