package com.zhenxi.hunter.obfuscator.gradle

import com.zhenxi.hunter.obfuscator.DexControlFlowObfuscator
import com.zhenxi.hunter.obfuscator.ObfuscatorConfig
import com.zhenxi.hunter.obfuscator.ObfuscatorLogger
import com.zhenxi.hunter.obfuscator.ObfuscatorStats
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.tasks.TaskProvider

/**
 * DEX 控制流混淆 Gradle 插件。
 *
 * 使用（宿主工程 app/build.gradle）：
 *   plugins { id 'com.zhenxi.dexcfgobf' }
 *   dexControlFlowObfuscator {
 *       enabled true
 *       obfClass = ["com.your.pkg"]
 *       blackClass = []
 *   }
 *
 * 原理见 com.zhenxi.hunter.obfuscator.CfgFlattener（基本块重排，dexlib2 具名 Label
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

        project.afterEvaluate {
            def androidExt = project.extensions.findByName('android')
            if (androidExt == null) {
                project.logger.warn('[dex-cfg-obf] no android extension; plugin does nothing (apply on an Android application module).')
                return
            }
            // 只处理 application 模块（有 applicationVariants）。
            if (!androidExt.hasProperty('applicationVariants')) {
                project.logger.warn('[dex-cfg-obf] android extension has no applicationVariants (library module?); skip.')
                return
            }

            androidExt.applicationVariants.configureEach { variant ->
                String variantName = variant.name
                String variantCap = capitalize(variantName)
                boolean isReleaseVariant = variant.buildType.name == 'release'

                boolean applyHere = ext.enabled && (!ext.onlyReleaseByDefault || isReleaseVariant)
                if (!applyHere) {
                    return
                }

                // 定位“产出最终 DEX”的上游任务：
                //  - minify 开启（release 典型）：minify<Variant>WithR8 直接产出最终 dex；
                //  - minify 关闭（debug 典型）：没有 R8，项目类由 mergeProjectDex<Variant> 合并产出。
                // 只混淆项目类（com.* 白名单），因此非 minify 时锚定 mergeProjectDex 足矣，
                // 不去碰 mergeExtDex/mergeLibDex（第三方库）。
                String r8Name = "minify${variantCap}WithR8"
                String mergeProjName = "mergeProjectDex${variantCap}"
                Task dexProducer = project.tasks.findByName(r8Name)
                String producerConventionalDir
                if (dexProducer != null) {
                    producerConventionalDir = "intermediates/dex/${variantName}/${r8Name}"
                } else {
                    dexProducer = project.tasks.findByName(mergeProjName)
                    producerConventionalDir = "intermediates/dex/${variantName}/${mergeProjName}"
                }
                if (dexProducer == null) {
                    project.logger.warn("[dex-cfg-obf] no ${r8Name} nor ${mergeProjName} task; skip ${variantName}")
                    return
                }
                final Task producer = dexProducer
                final String convDir = producerConventionalDir

                TaskProvider<Task> obfTask = project.tasks.register("obfuscate${variantCap}DexControlFlow") { t ->
                    t.group = 'obfuscation'
                    t.description = "Control-flow obfuscate ${variantName} DEX (after ${producer.name}, before packaging)."
                    t.outputs.upToDateWhen { false }
                    t.dependsOn producer

                    t.doLast {
                        ObfuscatorConfig config = new ObfuscatorConfig()
                        config.skipMethodsWithTryCatch = ext.skipMethodsWithTryCatch
                        config.maxInstructions = ext.maxInstructions
                        config.depth = ext.depth
                        if (ext.obfClass != null && !ext.obfClass.isEmpty()) {
                            config.includePrefixes.clear()
                            ext.obfClass.each { String c ->
                                String p = toDescriptorPrefix(c)
                                if (p != null) config.includePrefixes.add(p)
                            }
                        }
                        ext.blackClass.each { String c ->
                            String p = toDescriptorPrefix(c)
                            if (p != null) config.excludePrefixes.add(p)
                        }

                        List<File> dexDirs = []
                        producer.outputs.files.files.each { File f ->
                            if (f.isDirectory()) dexDirs.add(f)
                            else if (f.isFile() && f.name.endsWith('.dex')) dexDirs.add(f.parentFile)
                        }
                        File conventional = new File(project.buildDir, convDir)
                        if (conventional.isDirectory()) dexDirs.add(conventional)
                        dexDirs = dexDirs.findAll { it != null && it.isDirectory() }.unique { it.absolutePath }

                        if (dexDirs.isEmpty()) {
                            throw new GradleException("[dex-cfg-obf] no dex output dir found for ${variantName} (producer=${producer.name})")
                        }

                        ObfuscatorLogger obfLogger = new ObfuscatorLogger() {
                            @Override void info(String msg) { project.logger.lifecycle('[dex-cfg-obf] ' + msg) }
                            @Override void warn(String msg) { project.logger.warn('[dex-cfg-obf] ' + msg) }
                        }
                        DexControlFlowObfuscator obfuscator = new DexControlFlowObfuscator(config, obfLogger)

                        long totalObf = 0
                        dexDirs.each { File dir ->
                            ObfuscatorStats stats = obfuscator.obfuscateDexDirectory(dir)
                            totalObf += stats.methodsObfuscated
                            if (stats.dexFailed > 0) {
                                throw new GradleException("[dex-cfg-obf] ${stats.dexFailed} dex failed in ${dir}; failing build to avoid shipping half-obfuscated dex")
                            }
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

    /** "com.zhenxi" -> "com/zhenxi"；空/null 归一化为 null。 */
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
}
