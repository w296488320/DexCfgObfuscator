package com.hunter.dexcfgobf.gradle

import com.hunter.dexcfgobf.DexControlFlowObfuscator
import com.hunter.dexcfgobf.ObfuscatorConfig
import com.hunter.dexcfgobf.ObfuscatorLogger
import com.hunter.dexcfgobf.ObfuscatorStats
import com.hunter.dexcfgobf.ObfuscationReportWriter
import com.hunter.dexcfgobf.R8MappingResolver
import com.android.build.api.artifact.SingleArtifact
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.tasks.TaskProvider

/**
 * DEX 控制流混淆 Gradle 插件。
 *
 * 使用（宿主工程 app/build.gradle）：
 *   plugins { id 'com.hunter.dexcfgobf' }
 *   dexControlFlowObfuscator {
 *       enabled true
 *       level ObfuscationLevel.MEDIUM
 *       obfClass = ["com.your.pkg"]
 *       blackClass = []
 *   }
 *
 * 原理见 com.hunter.dexcfgobf.CfgFlattener（基本块重排，dexlib2 具名 Label
 * 自动重算偏移/升格 goto，规避 “Unsigned short value out of range: 65540”）。
 *
 * 时序：minify<Variant>WithR8 -> 【本混淆任务】-> package/mergeAssets。
 *   在 R8 产出最终 dex 之后、打包之前就地改写 dex。若宿主还生成了 dex 完整性清单
 *   （如 generate<Variant>ApkIntegrityAsset），本插件会让该任务依赖混淆任务，
 *   保证清单记录的是“混淆后”的 dex hash，运行时自检不自伤。
 */
class DexCfgObfuscatorPlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        DexCfgObfuscatorExtension ext = project.extensions.create(
                'dexControlFlowObfuscator', DexCfgObfuscatorExtension)

        project.pluginManager.withPlugin('com.android.application') {
            def androidComponents = project.extensions.findByName('androidComponents')
            if (androidComponents == null) {
                throw new GradleException('[dex-cfg-obf] androidComponents extension unavailable')
            }
            // AGP 7+ 正式 Variant API；不再使用 afterEvaluate/applicationVariants。
            androidComponents.onVariants(androidComponents.selector().all()) { variant ->
                String variantName = variant.name
                String variantCap = capitalize(variantName)

                if (!ext.enabled) {
                    return
                }

                // 定位“产出最终 DEX”的上游任务：
                //  - minify 开启（release 典型）：minify<Variant>WithR8 直接产出最终 dex；
                //  - minify 关闭（debug 典型）：没有 R8，项目类由 mergeProjectDex<Variant> 合并产出。
                // 只混淆项目类（com.* 白名单），因此非 minify 时锚定 mergeProjectDex 足矣，
                // 不去碰 mergeExtDex/mergeLibDex（第三方库）。
                String r8Name = "minify${variantCap}WithR8"
                String mergeProjName = "mergeProjectDex${variantCap}"
                final boolean useR8Mapping = variant.minifyEnabled
                final String convDir = "intermediates/dex/${variantName}/" +
                        (useR8Mapping ? r8Name : mergeProjName)
                def mappingProvider = useR8Mapping
                        ? variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE.INSTANCE)
                        : null

                TaskProvider<Task> obfTask = project.tasks.register("obfuscate${variantCap}DexControlFlow") { t ->
                    t.group = 'obfuscation'
                    t.description = "Control-flow obfuscate ${variantName} DEX after its final DEX producer."
                    t.outputs.upToDateWhen { false }
                    // TaskCollection 是惰性的：producer 即使稍后才由 AGP 注册，也会自动纳入依赖，
                    // 且不会在 producer 创建回调里嵌套 configure（Gradle 9 MutationGuard 禁止后者）。
                    t.dependsOn(project.tasks.matching { it.name == r8Name || it.name == mergeProjName })

                    t.doLast {
                        Task producer = project.tasks.findByName(useR8Mapping ? r8Name : mergeProjName)
                        if (producer == null) {
                            // 某些 AGP 补丁版的 minify 标志/任务名可能变化；仅在实际执行时探测兜底。
                            producer = project.tasks.findByName(r8Name) ?: project.tasks.findByName(mergeProjName)
                        }
                        if (producer == null) {
                            throw new GradleException("[dex-cfg-obf] no ${r8Name} nor ${mergeProjName} task for ${variantName}")
                        }
                        ObfuscatorConfig config = new ObfuscatorConfig()
                        if (ext.level == null) {
                            throw new GradleException('[dex-cfg-obf] level must not be null')
                        }
                        config.depth = ext.level.depth
                        if (ext.obfClass != null && !ext.obfClass.isEmpty()) {
                            config.includePrefixes.clear()
                            ext.obfClass.each { String c ->
                                String p = toDescriptorPrefix(c)
                                if (p != null) config.includePrefixes.add(p)
                            }
                        }
                        if (ext.blackClass != null) {
                            ext.blackClass.each { String c ->
                                String p = toDescriptorPrefix(c)
                                if (p != null) config.excludePrefixes.add(p)
                            }
                        }

                        // release/minify 路径必须先等 R8 完成，再用 mapping.txt 把“原始业务类白名单”
                        // 精确映射到最终 DEX 类名。不能直接包含 -repackageclasses 的目标包，
                        // 否则会漏掉改名后的业务类，或误伤同样被重打包的第三方类。
                        if (useR8Mapping) {
                            File mapping = null
                            try {
                                mapping = mappingProvider?.get()?.asFile
                            } catch (Throwable ignored) {
                                // 兼容尚未暴露 mapping artifact 的 AGP 补丁版，下面走受限兜底。
                            }
                            if (mapping == null || !mapping.isFile()) {
                                mapping = findR8Mapping(project, variantName, producer)
                            }
                            if (mapping == null) {
                                throw new GradleException("[dex-cfg-obf] R8 mapping.txt not found for ${variantName}; " +
                                        "refusing prefix-only post-R8 obfuscation")
                            }
                            int resolved = R8MappingResolver.apply(mapping, config)
                            if (resolved == 0) {
                                throw new GradleException("[dex-cfg-obf] R8 mapping resolved zero included classes for ${variantName}; " +
                                        "check obfClass/blackClass")
                            }
                            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: R8 mapping resolved ${resolved} final class descriptor(s) from ${mapping}")
                        }

                        List<File> dexDirs = []
                        producer.outputs.files.files.each { File f ->
                            if (f.isDirectory()) dexDirs.add(f)
                            else if (f.isFile() && f.name.endsWith('.dex')) dexDirs.add(f.parentFile)
                        }
                        File conventional = new File(project.buildDir, convDir)
                        if (conventional.isDirectory()) dexDirs.add(conventional)
                        dexDirs = collapseNestedDexDirs(
                                dexDirs.findAll { it != null && it.isDirectory() }.unique { it.canonicalPath })
                                .findAll { containsDex(it) }

                        if (dexDirs.isEmpty()) {
                            throw new GradleException("[dex-cfg-obf] no dex output dir found for ${variantName} (producer=${producer.name})")
                        }

                        ObfuscatorLogger obfLogger = new ObfuscatorLogger() {
                            @Override void info(String msg) { project.logger.lifecycle('[dex-cfg-obf] ' + msg) }
                            @Override void warn(String msg) { project.logger.warn('[dex-cfg-obf] ' + msg) }
                        }
                        DexControlFlowObfuscator obfuscator = new DexControlFlowObfuscator(config, obfLogger)

                        long totalObf = 0
                        ObfuscatorStats combinedStats = new ObfuscatorStats()
                        dexDirs.each { File dir ->
                            ObfuscatorStats stats = obfuscator.obfuscateDexDirectory(dir)
                            combinedStats.mergeFrom(stats)
                            totalObf += stats.methodsObfuscated
                            if (stats.dexFailed > 0) {
                                throw new GradleException("[dex-cfg-obf] ${stats.dexFailed} dex failed in ${dir}; failing build to avoid shipping half-obfuscated dex")
                            }
                        }
                        if (config.reportEnabled) {
                            File reportFile = new File(project.buildDir,
                                    "reports/dex-cfg-obfuscator/${variantName}.json")
                            ObfuscationReportWriter.write(reportFile, variantName, config, combinedStats)
                            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: report ${reportFile}")
                            runAdversarialCommands(ext.adversarialCommands, dexDirs, reportFile,
                                    variantName, ext.adversarialTimeoutSeconds, project)
                        }
                        project.logger.lifecycle("[dex-cfg-obf] ${variantName}: obfuscated ${totalObf} methods across ${dexDirs.size()} dex dir(s)")
                    }
                }

                // 若宿主生成 dex 完整性清单，让它在混淆之后运行（记录混淆后的 hash）。
                // 惰性 matching：对“将来才注册”的任务也生效。
                project.tasks.matching { it.name == "generate${variantCap}ApkIntegrityAsset" }
                        .configureEach { it.dependsOn obfTask }
                // 兜底：插到 dex 产出与 打包/合并assets 之间。
                project.tasks.matching { it.name == "package${variantCap}" || it.name == "merge${variantCap}Assets" }
                        .configureEach { it.dependsOn obfTask }
            }
        }
    }

    /** "com.example" -> "com/example"；空/null 归一化为 null。 */
    private static String toDescriptorPrefix(String pkgOrClass) {
        if (pkgOrClass == null) return null
        String t = pkgOrClass.trim()
        if (t.isEmpty()) return null
        return t.replace('.', '/')
    }

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) return s
        return Character.toString(Character.toUpperCase(s.charAt(0))) + s.substring(1)
    }

    /** 优先使用 AGP 的标准 mapping 输出；兼容 producer 直接声明 mapping.txt 的版本。 */
    private static File findR8Mapping(Project project, String variantName, Task producer) {
        File conventional = new File(project.buildDir, "outputs/mapping/${variantName}/mapping.txt")
        if (conventional.isFile()) return conventional
        for (File f : producer.outputs.files.files) {
            if (f.isFile() && f.name == 'mapping.txt') return f
            if (f.isDirectory()) {
                File nested = new File(f, 'mapping.txt')
                if (nested.isFile()) return nested
            }
        }
        return null
    }

    /** producer 同时声明父/子输出目录时只保留父目录，避免递归扫描同一 DEX 两次。 */
    private static List<File> collapseNestedDexDirs(List<File> dirs) {
        List<File> ordered = new ArrayList<>(dirs)
        ordered.sort { a, b -> a.canonicalPath.length() <=> b.canonicalPath.length() }
        List<File> result = []
        for (File candidate : ordered) {
            String path = candidate.canonicalPath
            boolean nested = result.any { File parent ->
                String pp = parent.canonicalPath
                path == pp || path.startsWith(pp + File.separator)
            }
            if (!nested) result.add(candidate)
        }
        return result
    }

    /** 过滤 R8 同时声明的资源等输出目录，目录计数只统计实际含 DEX 的项。 */
    private static boolean containsDex(File dir) {
        File[] children = dir?.listFiles()
        if (children == null) return false
        for (File child : children) {
            if (child.isFile() && child.name.endsWith('.dex')) return true
            if (child.isDirectory() && containsDex(child)) return true
        }
        return false
    }

    /** 可选 JADX/ReDex/自研恢复器入口；使用 ProcessBuilder，避免命令经 shell 二次解释。 */
    private static void runAdversarialCommands(List<List<String>> configured,
                                               List<File> dexDirs,
                                               File report,
                                               String variant,
                                               int timeoutSeconds,
                                               Project project) {
        if (configured == null || configured.isEmpty()) return
        File logDir = new File(project.buildDir, "reports/dex-cfg-obfuscator/adversarial/${variant}")
        if (!logDir.isDirectory() && !logDir.mkdirs() && !logDir.isDirectory()) {
            throw new GradleException("[dex-cfg-obf] cannot create adversarial log dir ${logDir}")
        }
        int run = 0
        configured.each { List<String> raw ->
            if (raw == null || raw.isEmpty()) {
                throw new GradleException('[dex-cfg-obf] adversarialCommands contains an empty command')
            }
            dexDirs.each { File dexDir ->
                List<String> command = raw.collect { String arg ->
                    arg.replace('{dexDir}', dexDir.absolutePath)
                            .replace('{report}', report.absolutePath)
                            .replace('{variant}', variant)
                }
                File log = new File(logDir, String.format(java.util.Locale.US, '%02d.log', run++))
                Process process = new ProcessBuilder(command)
                        .directory(project.rootDir)
                        .redirectErrorStream(true)
                        .redirectOutput(log)
                        .start()
                boolean exited = process.waitFor(Math.max(1, timeoutSeconds), java.util.concurrent.TimeUnit.SECONDS)
                if (!exited) {
                    process.destroyForcibly()
                    throw new GradleException("[dex-cfg-obf] adversarial command timed out: ${command}; log=${log}")
                }
                if (process.exitValue() != 0) {
                    throw new GradleException("[dex-cfg-obf] adversarial command failed (${process.exitValue()}): ${command}; log=${log}")
                }
                project.logger.lifecycle("[dex-cfg-obf] adversarial command passed: ${command[0]} log=${log}")
            }
        }
    }

}
