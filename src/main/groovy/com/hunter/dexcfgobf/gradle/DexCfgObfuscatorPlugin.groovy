package com.hunter.dexcfgobf.gradle

import com.hunter.dexcfgobf.DexControlFlowObfuscator
import com.hunter.dexcfgobf.DexDirectoryState
import com.hunter.dexcfgobf.BuildEvidenceStore
import com.hunter.dexcfgobf.ObfuscatorConfig
import com.hunter.dexcfgobf.ObfuscatorLogger
import com.hunter.dexcfgobf.ObfuscatorStats
import com.hunter.dexcfgobf.ObfuscationReportWriter
import com.hunter.dexcfgobf.R8MappingResolver
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.ScopedArtifacts
import com.hunter.dexcfgobf.string.GenerateStringDecryptorTask
import com.hunter.dexcfgobf.string.GenerateStringProtectionRulesTask
import com.hunter.dexcfgobf.string.StringEncryptionContext
import com.hunter.dexcfgobf.string.StringClassConstantPoolCompactor
import com.hunter.dexcfgobf.string.StringEncryptionRegistry
import com.hunter.dexcfgobf.string.StringEncryptionSnapshot
import com.hunter.dexcfgobf.string.StringEncryptionVisitorFactory
import com.hunter.dexcfgobf.string.StringPlaintextVerifier
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.flow.FlowProviders
import org.gradle.api.flow.FlowScope
import org.gradle.api.tasks.TaskProvider
import javax.inject.Inject

/**
 * DEX 控制流混淆 Gradle 插件。
 *
 * 使用（宿主工程 app/build.gradle）：
 *   plugins { id 'com.hunter.dexcfgobf' }
 *   dexControlFlowObfuscator {
 *       dexObfuscator {
 *           enabled true
 *           level ObfuscationLevel.MEDIUM
 *           obfClass = ["com.your.pkg"]
 *           blackClass = []
 *       }
 *       stringEncryption {
 *           enabled true
 *           packages = ["com.your.pkg"]
 *       }
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
    private static final String STRING_EVIDENCE_DIGEST_VERSION =
            'string-evidence-v4-method-marker-usage-seeds'
    private static final String LIBRARY_STRING_EVIDENCE_DIGEST_VERSION =
            'library-string-evidence-v4-method-marker-usage-seeds'
    private static final String LIBRARY_EVIDENCE_DIGEST_PROPERTY =
            'dexCfgObfuscatorLibraryStringTransformDigest'
    private static final String LIBRARY_EVIDENCE_MINIFIED_PROPERTY =
            'dexCfgObfuscatorLibraryVariantMinified'
    private static final String LIBRARY_REQUIRED_DECRYPTOR_METHODS_PROPERTY =
            'dexCfgObfuscatorLibraryRequiredDecryptorOriginalMethodKeys'
    private final FlowScope flowScope
    private final FlowProviders flowProviders
    private final Set<String> registeredLibraryLockReleases =
            java.util.concurrent.ConcurrentHashMap.newKeySet()

    @Inject
    DexCfgObfuscatorPlugin(FlowScope flowScope, FlowProviders flowProviders) {
        this.flowScope = flowScope
        this.flowProviders = flowProviders
    }

    @Override
    void apply(Project project) {
        DexCfgObfuscatorExtension ext = project.extensions.create(
                'dexControlFlowObfuscator', DexCfgObfuscatorExtension)

        // library 没有最终 application DEX，仍可使用同一插件的前置字符串阶段。
        project.pluginManager.withPlugin('com.android.library') {
            def androidComponents = project.extensions.findByName('androidComponents')
            if (androidComponents == null) {
                throw new GradleException('[dex-cfg-obf] androidComponents extension unavailable')
            }
            androidComponents.onVariants(androidComponents.selector().all()) { variant ->
                warnLegacyCfgDslOnce(project, ext)
                String variantName = variant.name
                String variantCap = capitalize(variantName)
                String buildTypeName = variant.buildType == null
                        ? null : variant.buildType.toString()
                boolean failOnUnknownCoverage = ext.stringEncryption.failOnUnknownCoverage &&
                        isVariantSelected(ext.stringEncryption.failOnUnknownCoverageVariants,
                                variantName, buildTypeName,
                                'stringEncryption.failOnUnknownCoverageVariants')
                if (!(ext.stringEncryption.dependencyEvidenceProjects ?: []).isEmpty()
                        || !(ext.stringEncryption.dependencyEvidenceVariants ?: []).isEmpty()) {
                    throw new GradleException('[dex-cfg-obf] stringEncryption.' +
                            'dependencyEvidenceProjects/dependencyEvidenceVariants are ' +
                            'application-only; library project ' +
                            "${project.path} cannot aggregate another library's final-DEX evidence")
                }
                boolean stringEnabled = isStringEnabledForVariant(
                        ext.stringEncryption.enabled,
                        ext.stringEncryption.enabledVariants,
                        variantName, buildTypeName)
                if (stringEnabled) {
                    String registryKey = configureStringEncryption(
                            project, variant, ext, variantName, variantCap, false,
                            false, failOnUnknownCoverage)
                    TaskProvider<StringClassInventoryTask> classInventory =
                            registerStringClassInventory(project, variant, variantName, variantCap,
                                    ScopedArtifacts.Scope.PROJECT)
                    registerLibraryConstantPoolCompaction(project, variantName, variantCap,
                            registryKey, classInventory, ext.stringEncryption, variant.minifyEnabled,
                            failOnUnknownCoverage)
                }
            }
        }

        project.pluginManager.withPlugin('com.android.application') {
            def androidComponents = project.extensions.findByName('androidComponents')
            if (androidComponents == null) {
                throw new GradleException('[dex-cfg-obf] androidComponents extension unavailable')
            }
            // AGP 7+ 正式 Variant API；不再使用 afterEvaluate/applicationVariants。
            androidComponents.onVariants(androidComponents.selector().all()) { variant ->
                warnLegacyCfgDslOnce(project, ext)
                DexObfuscatorExtension cfg = ext.dexObfuscator
                String variantName = variant.name
                String variantCap = capitalize(variantName)
                String buildTypeName = variant.buildType == null
                        ? null : variant.buildType.toString()
                // 新模块只有 enabled 开关，true 对全部 application variant 生效。
                // legacyEnabledVariantsForPlugin 仅为 0.0.15 平铺 DSL 保留一版兼容行为。
                boolean cfgEnabled = isCfgEnabledForVariant(cfg.enabled,
                        ext.legacyEnabledVariantsForPlugin(), variantName, buildTypeName)
                boolean failOnUnknownCoverage = ext.stringEncryption.failOnUnknownCoverage &&
                        isVariantSelected(ext.stringEncryption.failOnUnknownCoverageVariants,
                                variantName, buildTypeName,
                                'stringEncryption.failOnUnknownCoverageVariants')
                boolean aggregateDependencyEvidence = isVariantSelected(
                        ext.stringEncryption.dependencyEvidenceVariants,
                        variantName, buildTypeName,
                        'stringEncryption.dependencyEvidenceVariants')
                List<String> dependencyEvidenceProjects = aggregateDependencyEvidence
                        ? validateDependencyEvidenceProjects(project,
                                ext.stringEncryption.dependencyEvidenceProjects)
                        : Collections.emptyList()

                // 两个模块独立；字符串阶段可由全局开关或非空 selector 启用。
                boolean stringEnabled = isStringEnabledForVariant(
                        ext.stringEncryption.enabled,
                        ext.stringEncryption.enabledVariants,
                        variantName, buildTypeName)
                String stringRegistryKey = stringEnabled
                        ? configureStringEncryption(project, variant, ext, variantName, variantCap,
                                cfgEnabled, true, failOnUnknownCoverage)
                        : null
                TaskProvider<StringClassInventoryTask> stringClassInventory =
                        stringRegistryKey == null ? null : registerStringClassInventory(
                                project, variant, variantName, variantCap,
                                ScopedArtifacts.Scope.ALL)

                if (!dependencyEvidenceProjects.isEmpty() && stringRegistryKey == null) {
                    throw new GradleException('[dex-cfg-obf] stringEncryption.' +
                            'dependencyEvidenceProjects requires stringEncryption to be enabled ' +
                            'for the current variant')
                }

                if (!cfgEnabled) {
                    if (stringRegistryKey != null) {
                        registerStringOnlyVerificationTask(project, variant, ext, variantName,
                                variantCap, stringRegistryKey, stringClassInventory,
                                dependencyEvidenceProjects,
                                failOnUnknownCoverage)
                    }
                    return
                }

                // 定位“产出最终 DEX”的上游任务：
                //  - minify 开启（release 典型）：minify<Variant>WithR8 直接产出最终 dex；
                //  - minify 关闭（debug 典型）：优先使用只含项目类的 mergeProjectDex<Variant>；
                //  - 部分 application/AGP 任务图不提供 mergeProjectDex，则回退到 mergeDex<Variant>。
                // mergeDex 可能同时包含依赖类，但 shouldProcessClass 仍只处理显式业务白名单，
                // 且绝不单独处理 mergeExtDex/mergeLibDex。
                String r8Name = "minify${variantCap}WithR8"
                String mergeProjName = "mergeProjectDex${variantCap}"
                String mergeDexName = "mergeDex${variantCap}"
                String mergeExtDexName = "mergeExtDex${variantCap}"
                String mergeLibDexName = "mergeLibDex${variantCap}"
                final boolean useR8Mapping = variant.minifyEnabled
                def mappingProvider = useR8Mapping
                        ? variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE.INSTANCE)
                        : null

                TaskProvider<Task> obfTask = project.tasks.register("obfuscate${variantCap}DexControlFlow") { t ->
                    t.group = 'obfuscation'
                    t.description = "Control-flow obfuscate ${variantName} DEX after its final DEX producer."
                    t.outputs.upToDateWhen { false }
                    if (stringClassInventory != null) t.dependsOn(stringClassInventory)
                    DexCfgObfuscatorPlugin.configureDependencyEvidenceTaskDependencies(t, project,
                            dependencyEvidenceProjects, variantCap)
                    // 只依赖一个 primary producer，避免某些 AGP 同时暴露 mergeProjectDex 与
                    // downstream mergeDex 时，后者抢在本任务前消费尚未混淆的项目 DEX。
                    // Closure 在任务图解析时求值，此时 AGP 的任务已全部注册。
                    t.dependsOn({ ignored -> DexCfgObfuscatorPlugin.requirePrimaryDexProducer(
                            project, useR8Mapping, r8Name, mergeProjName, mergeDexName,
                            variantName) })
                    // 非 minified application 的最终 APK 由 project/lib/ext 三组 DEX 输入组成；
                    // ext/lib 只用于字符串明文只读审计，不进入 CFG 改写。
                    if (stringRegistryKey != null && !useR8Mapping) {
                        t.dependsOn(project.tasks.matching {
                            it.name == mergeExtDexName || it.name == mergeLibDexName
                                    || it.name == "generate${variantCap}GlobalSynthetics"
                        })
                    }

                    t.doLast {
                        Task producer = DexCfgObfuscatorPlugin.requirePrimaryDexProducer(
                                project, useR8Mapping, r8Name, mergeProjName, mergeDexName,
                                variantName)
                        project.logger.lifecycle("[dex-cfg-obf] ${variantName}: producer ${producer.name}")
                        ObfuscatorConfig config = new ObfuscatorConfig()
                        if (cfg.level == null) {
                            throw new GradleException(
                                    '[dex-cfg-obf] dexObfuscator.level must not be null')
                        }
                        config.depth = cfg.level.depth
                        DexCfgObfuscatorPlugin.applyQualityBudgets(cfg, config)
                        config.refuseAlreadyObfuscatedInput = true
                        if (cfg.obfClass != null && !cfg.obfClass.isEmpty()) {
                            config.includePrefixes.clear()
                            cfg.obfClass.each { String c ->
                                String p = DexCfgObfuscatorPlugin.toDescriptorPrefix(c)
                                if (p != null) config.includePrefixes.add(p)
                            }
                        }
                        if (cfg.blackClass != null) {
                            cfg.blackClass.each { String c ->
                                String p = DexCfgObfuscatorPlugin.toDescriptorPrefix(c)
                                if (p != null) config.excludePrefixes.add(p)
                            }
                        }

                        // Validate every dependency artifact/evidence before writing any CFG pending
                        // marker or mutating producer DEX. The later final-Dex merge reuses the same
                        // fail-closed checks; this early pass keeps a bad library from failing only
                        // after the application DEX has already been rewritten.
                        if (!dependencyEvidenceProjects.isEmpty()) {
                            ObfuscatorStats dependencyPreflightStats = new ObfuscatorStats()
                            dependencyPreflightStats.stringCoverageStatus = 'FULL'
                            dependencyPreflightStats.stringEncryptionMode =
                                    StringEncryptionRegistry.snapshot(stringRegistryKey).mode
                            dependencyPreflightStats.stringTransformDigest =
                                    DexCfgObfuscatorPlugin.configurationDigest(
                                    STRING_EVIDENCE_DIGEST_VERSION,
                                    stringRegistryKey)
                            DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(
                                    project, dependencyEvidenceProjects,
                                    variantName, variantCap,
                                    new StringEvidenceScope(Collections.emptySet(),
                                            Collections.emptyMap(), Collections.emptyMap(),
                                            Collections.emptyMap()), dependencyPreflightStats,
                                    failOnUnknownCoverage,
                                    ext.stringEncryption.maxUnsafeSkippedStrings,
                                    ext.stringEncryption.maxFilteredStrings)
                        }

                        // release/minify 路径必须先等 R8 完成，再用 mapping.txt 把“原始业务类白名单”
                        // 精确映射到最终 DEX 类名。不能直接包含 -repackageclasses 的目标包，
                        // 否则会漏掉改名后的业务类，或误伤同样被重打包的第三方类。
                        File r8MappingFile = null
                        if (useR8Mapping) {
                            try {
                                r8MappingFile = mappingProvider?.get()?.asFile
                            } catch (Throwable ignored) {
                                // 兼容尚未暴露 mapping artifact 的 AGP 补丁版，下面走受限兜底。
                            }
                            if (r8MappingFile == null || !r8MappingFile.isFile()) {
                                r8MappingFile = DexCfgObfuscatorPlugin.findR8Mapping(
                                        project, variantName, producer)
                            }
                            if (r8MappingFile == null) {
                                throw new GradleException("[dex-cfg-obf] R8 mapping.txt not found for ${variantName}; " +
                                        "refusing prefix-only post-R8 obfuscation")
                            }
                            int resolved = R8MappingResolver.apply(r8MappingFile, config)
                            if (resolved == 0) {
                                throw new GradleException("[dex-cfg-obf] R8 mapping resolved zero included classes for ${variantName}; " +
                                        "check obfClass/blackClass")
                            }
                            int memberOnlyOwners = config.resolvedIncludeClasses.count {
                                !config.resolvedClassWideIncludeClasses.contains(it)
                            }
                            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: R8 mapping " +
                                    "resolved ${config.resolvedClassWideIncludeClasses.size()} " +
                                    "class-wide owner(s), ${memberOnlyOwners} member-only owner(s), " +
                                    "and ${config.resolvedIncludeMethods.size()} exact final " +
                                    "method name(s) from ${r8MappingFile}")
                        }
                        if (stringRegistryKey != null &&
                                ext.stringEncryption.failOnUnprotectedDecryptor) {
                            Set<String> requiredOriginalMethods =
                                    DexCfgObfuscatorPlugin.collectRequiredDecryptorOriginalMethods(
                                            project,
                                            dependencyEvidenceProjects, variantCap, variantName,
                                            DexCfgObfuscatorPlugin.
                                                    discoverRequiredDecryptorOriginalMethods(
                                                            project, variantCap, variantName,
                                                            stringRegistryKey))
                            DexCfgObfuscatorPlugin.configureRequiredDecryptorMethods(config,
                                    requiredOriginalMethods,
                                    useR8Mapping, r8MappingFile, variantName)
                        }

                        List<File> dexDirs = DexCfgObfuscatorPlugin.findDexDirectories(
                                project, variantName, producer)

                        if (dexDirs.isEmpty()) {
                            throw new GradleException("[dex-cfg-obf] no dex output dir found for ${variantName} (producer=${producer.name})")
                        }
                        List<File> stringAuditDexDirs =
                                DexCfgObfuscatorPlugin.findStringAuditDexDirectories(
                                        project, variantCap, dexDirs, useR8Mapping)

                        File stateRoot = new File(project.buildDir,
                                "intermediates/dex-cfg-obfuscator-state/${variantName}")
                        File evidenceRoot = new File(project.buildDir,
                                "intermediates/dex-cfg-obfuscator-evidence/${variantName}")
                        String cfgDigest = DexCfgObfuscatorPlugin.cfgTransformDigest(config)
                        File reportFile = config.reportEnabled ? new File(project.buildDir,
                                "reports/dex-cfg-obfuscator/${variantName}.json") : null
                        String variantLockDigest = DexCfgObfuscatorPlugin.configurationDigest(
                                'application-variant-transaction-v1',
                                project.buildDir.canonicalPath, variantName)
                        File variantLockFile = new File(project.buildDir.parentFile,
                                ".gradle/dex-cfg-obfuscator-locks/${variantLockDigest}.lock")
                        VariantArtifactTransaction artifactTransaction = null
                        Throwable artifactPipelineFailure = null
                        Map<String, String> transactionInputFingerprints = new TreeMap<>()
                        Set<String> transactionFreshDexDirs = new TreeSet<>()
                        try {
                            try {
                                artifactTransaction = VariantArtifactTransaction.begin(
                                        variantLockFile)
                            } catch (Exception lockFailure) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: cannot " +
                                        'acquire the variant artifact transaction lock', lockFailure)
                            }

                            // Capture every exact sidecar before even the read-only fresh/cached pass.
                            // Cached DEX bytes are never captured or changed, but their state/pending files
                            // can be repaired by the existing path and must roll back if a later gate fails.
                            dexDirs.each { File dir ->
                                artifactTransaction.captureFile(
                                        DexDirectoryState.stateFile(stateRoot, dir), project.buildDir)
                                artifactTransaction.captureFile(
                                        BuildEvidenceStore.cfgEvidenceFile(evidenceRoot, dir),
                                        project.buildDir)
                                artifactTransaction.captureFile(
                                        BuildEvidenceStore.cfgPendingFile(evidenceRoot, dir),
                                        project.buildDir)
                            }
                            if (stringRegistryKey != null) {
                                artifactTransaction.captureFile(
                                        BuildEvidenceStore.stringEvidenceFile(
                                                evidenceRoot, variantName), project.buildDir)
                            }
                            if (reportFile != null) {
                                artifactTransaction.captureFile(reportFile, project.buildDir)
                            }

                            // First pass is deliberately read-only. It identifies every directory that can
                            // reach writeCfgPending/obfuscateDexDirectory, then snapshots all of their DEX
                            // files before the first directory is allowed to mutate.
                            dexDirs.each { File dir ->
                                String canonicalDir = dir.canonicalPath
                                String inputFingerprint
                                try {
                                    inputFingerprint = DexDirectoryState.fingerprint(dir)
                                } catch (Exception stateFailure) {
                                    throw new GradleException("[dex-cfg-obf] cannot fingerprint ${dir}; " +
                                            'refusing to start the variant artifact transaction',
                                            stateFailure)
                                }
                                transactionInputFingerprints.put(canonicalDir, inputFingerprint)
                                Optional<BuildEvidenceStore.CfgPendingEvidence> pending
                                try {
                                    pending = BuildEvidenceStore.readCfgPending(
                                            BuildEvidenceStore.cfgPendingFile(evidenceRoot, dir))
                                } catch (Exception pendingFailure) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: CFG " +
                                            "transaction marker is corrupt/unreadable for ${dir}; run " +
                                            'clean --rerun-tasks', pendingFailure)
                                }
                                // A marker whose pre-image no longer matches wins over otherwise valid
                                // per-directory evidence: the process may have died after CFG commit but
                                // before the variant-wide string/quality gates completed.
                                if (pending.isPresent()
                                        && inputFingerprint != pending.get().getPreFingerprint()) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: an earlier " +
                                            "variant transaction changed ${dir} but did not complete " +
                                            'every post-CFG gate; refusing to trust its partial commit. ' +
                                            'Run clean --rerun-tasks')
                                }
                                Optional<BuildEvidenceStore.CfgEvidence> evidence
                                try {
                                    evidence = BuildEvidenceStore.readCfg(
                                            BuildEvidenceStore.cfgEvidenceFile(evidenceRoot, dir))
                                } catch (Exception evidenceFailure) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: CFG " +
                                            "evidence is corrupt/unreadable for ${dir}; run a clean " +
                                            '--rerun-tasks build', evidenceFailure)
                                }
                                if (evidence.isPresent()
                                        && inputFingerprint == evidence.get().getPostFingerprint()) {
                                    if (cfgDigest != evidence.get().getCfgTransformDigest()) {
                                        throw new GradleException("[dex-cfg-obf] ${variantName}: current " +
                                                'DEX was produced by a different CFG transform ' +
                                                'configuration; run clean with --rerun-tasks instead ' +
                                                'of relabeling it')
                                    }
                                    return
                                }
                                File stateFile = DexDirectoryState.stateFile(stateRoot, dir)
                                if (DexDirectoryState.matches(stateFile, inputFingerprint)) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: DEX state " +
                                            'says the artifact is already obfuscated, but matching CFG ' +
                                            'evidence is unavailable; run clean with --rerun-tasks')
                                }
                                transactionFreshDexDirs.add(canonicalDir)
                            }
                            dexDirs.findAll {
                                transactionFreshDexDirs.contains(it.canonicalPath)
                            }.each { File freshDir ->
                                artifactTransaction.captureDexDirectory(freshDir)
                            }

                        ObfuscatorLogger obfLogger = new ObfuscatorLogger() {
                            @Override void info(String msg) { project.logger.lifecycle('[dex-cfg-obf] ' + msg) }
                            @Override void warn(String msg) { project.logger.warn('[dex-cfg-obf] ' + msg) }
                        }
                        DexControlFlowObfuscator obfuscator = new DexControlFlowObfuscator(config, obfLogger)

                        long totalObf = 0
                        int skippedDexDirs = 0
                        int processedDexDirs = 0
                        ObfuscatorStats combinedStats = new ObfuscatorStats()
                        dexDirs.each { File dir ->
                            File stateFile
                            File evidenceFile
                            File pendingFile
                            File lockFile
                            java.nio.channels.FileChannel lockChannel = null
                            java.nio.channels.FileLock transactionLock = null
                            try {
                                stateFile = DexDirectoryState.stateFile(stateRoot, dir)
                                evidenceFile = BuildEvidenceStore.cfgEvidenceFile(evidenceRoot, dir)
                                pendingFile = BuildEvidenceStore.cfgPendingFile(evidenceRoot, dir)
                                lockFile = BuildEvidenceStore.cfgLockFile(evidenceRoot, dir)
                                java.nio.file.Files.createDirectories(lockFile.toPath().parent)
                                lockChannel = java.nio.channels.FileChannel.open(lockFile.toPath(),
                                        java.nio.file.StandardOpenOption.CREATE,
                                        java.nio.file.StandardOpenOption.WRITE)
                                transactionLock = lockChannel.lock()
                            } catch (Exception lockFailure) {
                                try { lockChannel?.close() } catch (Exception ignored) { }
                                throw new GradleException("[dex-cfg-obf] cannot acquire exclusive CFG " +
                                        "transaction lock for ${dir}", lockFailure)
                            }
                            try {
                            String inputFingerprint
                            try {
                                inputFingerprint = DexDirectoryState.fingerprint(dir)
                            } catch (Exception stateFailure) {
                                throw new GradleException("[dex-cfg-obf] cannot fingerprint ${dir}; " +
                                        "refusing to risk reprocessing an already-obfuscated DEX", stateFailure)
                            }
                            String transactionFingerprint = transactionInputFingerprints.get(
                                    dir.canonicalPath)
                            if (transactionFingerprint == null
                                    || inputFingerprint != transactionFingerprint) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: DEX input " +
                                        "changed after the variant transaction snapshot for ${dir}; " +
                                        'refusing an unjournaled rewrite')
                            }
                            Optional<BuildEvidenceStore.CfgEvidence> evidence
                            try {
                                evidence = BuildEvidenceStore.readCfg(evidenceFile)
                            } catch (Exception evidenceFailure) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: CFG evidence " +
                                        "is corrupt/unreadable for ${dir}; run a clean --rerun-tasks build",
                                        evidenceFailure)
                            }
                            if (evidence.isPresent()
                                    && inputFingerprint == evidence.get().getPostFingerprint()) {
                                if (cfgDigest != evidence.get().getCfgTransformDigest()) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: current DEX " +
                                            "was produced by a different CFG transform configuration; " +
                                            "run clean with --rerun-tasks instead of relabeling it")
                                }
                                ObfuscatorStats cachedStats = evidence.get().getStats()
                                combinedStats.mergeFrom(cachedStats)
                                totalObf += cachedStats.methodsObfuscated
                                skippedDexDirs++
                                // Evidence is authoritative. Repair a missing/stale legacy state sidecar so
                                // later tooling that still reads it cannot trigger a second transformation.
                                if (!DexDirectoryState.matches(stateFile, inputFingerprint)) {
                                    try {
                                        DexDirectoryState.write(stateFile, inputFingerprint)
                                    } catch (Exception stateFailure) {
                                        throw new GradleException("[dex-cfg-obf] ${variantName}: restored " +
                                                "CFG evidence but could not repair state for ${dir}", stateFailure)
                                    }
                                }
                                try {
                                    java.nio.file.Files.deleteIfExists(pendingFile.toPath())
                                } catch (Exception pendingCleanupFailure) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: verified " +
                                            "CFG evidence but could not clear a completed transaction " +
                                            "marker for ${dir}", pendingCleanupFailure)
                                }
                                project.logger.lifecycle("[dex-cfg-obf] ${variantName}: skip unchanged " +
                                        "already-obfuscated DEX dir ${dir}; restored verified CFG evidence")
                                return
                            }
                            if (DexDirectoryState.matches(stateFile, inputFingerprint)) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: DEX state says " +
                                        "the artifact is already obfuscated, but matching CFG evidence is " +
                                        "unavailable; run clean with --rerun-tasks")
                            }

                            Optional<BuildEvidenceStore.CfgPendingEvidence> pending
                            try {
                                pending = BuildEvidenceStore.readCfgPending(pendingFile)
                            } catch (Exception pendingFailure) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: CFG transaction " +
                                        "marker is corrupt/unreadable for ${dir}; run clean " +
                                        "--rerun-tasks", pendingFailure)
                            }
                            if (pending.isPresent()) {
                                if (inputFingerprint != pending.get().getPreFingerprint()) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: an earlier CFG " +
                                            "transaction changed ${dir} but did not commit matching " +
                                            "evidence; refusing to reprocess it. Run clean --rerun-tasks")
                                }
                                // The core transformer commits all changed DEX atomically. Matching the
                                // pre-image proves the previous transaction never committed and is safe to retry.
                                try {
                                    java.nio.file.Files.deleteIfExists(pendingFile.toPath())
                                } catch (Exception pendingCleanupFailure) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: cannot clear " +
                                            "an uncommitted CFG transaction marker for ${dir}",
                                            pendingCleanupFailure)
                                }
                            }
                            if (!transactionFreshDexDirs.contains(dir.canonicalPath)) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: CFG " +
                                        "disposition changed after transaction preflight for ${dir}; " +
                                        'refusing an unjournaled rewrite')
                            }
                            try {
                                BuildEvidenceStore.writeCfgPending(pendingFile, inputFingerprint,
                                        cfgDigest)
                            } catch (Exception pendingWriteFailure) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: cannot persist " +
                                        "the pre-transform CFG transaction marker for ${dir}; DEX was " +
                                        "not modified", pendingWriteFailure)
                            }

                            ObfuscatorStats stats
                            try {
                                stats = obfuscator.obfuscateDexDirectory(dir)
                            } catch (Throwable transformFailure) {
                                // Core transformation is staged and rolls back any partial commit. Only clear
                                // the marker after proving the producer bytes still equal the pre-image.
                                try {
                                    if (inputFingerprint == DexDirectoryState.fingerprint(dir)) {
                                        java.nio.file.Files.deleteIfExists(pendingFile.toPath())
                                    }
                                } catch (Throwable cleanupFailure) {
                                    transformFailure.addSuppressed(cleanupFailure)
                                }
                                throw transformFailure
                            }
                            if (stats.dexFailed > 0) {
                                throw new GradleException("[dex-cfg-obf] ${stats.dexFailed} dex failed in ${dir}; failing build to avoid shipping half-obfuscated dex")
                            }
                            try {
                                String postFingerprint = DexDirectoryState.fingerprint(dir)
                                stats.artifactFingerprint = postFingerprint
                                stats.cfgTransformDigest = cfgDigest
                                stats.evidenceSource = 'CURRENT_BUILD'
                                // Evidence is committed before the legacy state. The pending marker remains
                                // until every variant-wide string/quality gate succeeds; a hard kill after
                                // this point therefore fails closed on the next build.
                                BuildEvidenceStore.writeCfg(evidenceFile, postFingerprint,
                                        cfgDigest, stats)
                                DexDirectoryState.write(stateFile, postFingerprint)
                            } catch (Exception stateFailure) {
                                throw new GradleException("[dex-cfg-obf] transformed ${dir} but could not " +
                                        "record its post-transform fingerprint/evidence; run a clean build before retrying",
                                        stateFailure)
                            }
                            combinedStats.mergeFrom(stats)
                            totalObf += stats.methodsObfuscated
                            processedDexDirs++
                            } finally {
                                try { transactionLock?.release() } finally { lockChannel?.close() }
                            }
                        }
                        String stringDigest = stringRegistryKey == null ? ''
                                : DexCfgObfuscatorPlugin.configurationDigest(
                                        STRING_EVIDENCE_DIGEST_VERSION,
                                        stringRegistryKey)
                        boolean restoredStringEvidence = false
                        boolean currentStringEvidence = false
                        boolean missingStringEvidence = false
                        if (stringRegistryKey != null) {
                            StringEncryptionSnapshot snapshot = StringEncryptionRegistry.snapshot(stringRegistryKey)
                            String auditFingerprint
                            File stringEvidenceFile = BuildEvidenceStore.stringEvidenceFile(
                                    evidenceRoot, variantName)
                            try {
                                auditFingerprint = DexCfgObfuscatorPlugin
                                        .fingerprintDexDirectories(stringAuditDexDirs)
                            } catch (Exception fingerprintFailure) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: cannot fingerprint " +
                                        "all DEX inputs for string verification", fingerprintFailure)
                            }
                            ObfuscatorStats stringStats = new ObfuscatorStats()
                            Set<String> plaintextHashes = Collections.emptySet()
                            Map<String, Set<String>> plaintextHashesByOriginalClass =
                                    Collections.emptyMap()
                            Map<String, Set<String>> plaintextHashesByOriginalMethod =
                                    Collections.emptyMap()
                            Map<String, Set<String>> plaintextHashesByOriginalField =
                                    Collections.emptyMap()
                            Set<String> activeOriginalClasses =
                                    DexCfgObfuscatorPlugin.readStringClassInventory(
                                            stringClassInventory, variantName)
                            boolean fullCoverageProven =
                                    DexCfgObfuscatorPlugin.proveCurrentStringCoverage(
                                            project, stringRegistryKey, snapshot,
                                            activeOriginalClasses, variantName,
                                            failOnUnknownCoverage)
                            if (snapshot.classesVisited == 0) {
                                Optional<BuildEvidenceStore.StringEvidence> evidence
                                try {
                                    evidence = BuildEvidenceStore.readString(stringEvidenceFile,
                                            auditFingerprint, stringDigest)
                                } catch (Exception evidenceFailure) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: string " +
                                            "verification evidence is corrupt/unreadable; run a clean " +
                                            "--rerun-tasks build", evidenceFailure)
                                }
                                if (evidence.isPresent()) {
                                    restoredStringEvidence = true
                                    DexCfgObfuscatorPlugin.requireStringOwnerScope(
                                            evidence.get(), variantName,
                                            'application DEX')
                                    DexCfgObfuscatorPlugin.requireStringSkipReasonStats(evidence.get(),
                                            ext.stringEncryption.maxUnsafeSkippedStrings,
                                            ext.stringEncryption.maxFilteredStrings,
                                            variantName, 'application DEX')
                                    stringStats = evidence.get().getStats()
                                    plaintextHashes = evidence.get().getPlaintextSha256()
                                    plaintextHashesByOriginalClass =
                                            evidence.get().getPlaintextSha256ByOriginalClass()
                                    plaintextHashesByOriginalMethod =
                                            evidence.get().getPlaintextSha256ByOriginalMethod()
                                    plaintextHashesByOriginalField =
                                            evidence.get().getPlaintextSha256ByOriginalField()
                                    stringStats.stringCoverageStatus =
                                            DexCfgObfuscatorPlugin.
                                                    restoredApplicationStringCoverageStatus(
                                                            project,
                                                            evidence.get().getCoverageStatus())
                                    // Dependency counters are useful in the aggregate report, but
                                    // must never satisfy the application's own quality budget.
                                    DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                                            ext.stringEncryption,
                                            stringStats, variantName, failOnUnknownCoverage)
                                    StringEvidenceScope aggregateScope =
                                            DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(
                                                    project,
                                                    dependencyEvidenceProjects, variantName,
                                                    variantCap,
                                                    new StringEvidenceScope(plaintextHashes,
                                                            plaintextHashesByOriginalClass,
                                                            plaintextHashesByOriginalMethod,
                                                            plaintextHashesByOriginalField),
                                                    stringStats, failOnUnknownCoverage,
                                                    ext.stringEncryption.maxUnsafeSkippedStrings,
                                                    ext.stringEncryption.maxFilteredStrings)
                                    plaintextHashes = aggregateScope.plaintextHashes
                                    plaintextHashesByOriginalClass =
                                            aggregateScope.plaintextHashesByOriginalClass
                                    plaintextHashesByOriginalMethod =
                                            aggregateScope.plaintextHashesByOriginalMethod
                                    plaintextHashesByOriginalField =
                                            aggregateScope.plaintextHashesByOriginalField
                                    DexCfgObfuscatorPlugin.resetStringVerificationStats(
                                            stringStats, plaintextHashes.size())
                                    DexCfgObfuscatorPlugin.verifyFinalDexStrings(
                                            ext.stringEncryption, plaintextHashes,
                                            plaintextHashesByOriginalClass,
                                            plaintextHashesByOriginalMethod,
                                            plaintextHashesByOriginalField, stringAuditDexDirs,
                                            stringStats, variantName, project, useR8Mapping,
                                            r8MappingFile)
                                    project.logger.lifecycle("[dex-cfg-obf] ${variantName}: restored " +
                                            "string evidence bound to the current DEX artifact; " +
                                            "coverage=${stringStats.stringCoverageStatus}")
                                } else {
                                    Optional<BuildEvidenceStore.StringEvidence> priorEvidence
                                    try {
                                        priorEvidence = BuildEvidenceStore.readString(
                                                stringEvidenceFile)
                                    } catch (Exception evidenceFailure) {
                                        throw new GradleException("[dex-cfg-obf] ${variantName}: " +
                                                "prior string evidence is corrupt/unreadable; run " +
                                                "clean with --rerun-tasks", evidenceFailure)
                                    }
                                    boolean verifiedEmptyFullBuild =
                                            !priorEvidence.isPresent() &&
                                            fullCoverageProven
                                    if (!priorEvidence.isPresent() && !verifiedEmptyFullBuild) {
                                        missingStringEvidence = true
                                        throw new GradleException("[dex-cfg-obf] ${variantName}: " +
                                                "no prior string evidence is available for the " +
                                                "changed final DEX; run clean with --rerun-tasks")
                                    }
                                    DexCfgObfuscatorPlugin.
                                            requireExecutedAsmTransformForZeroVisitReconciliation(
                                                    project, variantCap, variantName)
                                    StringEvidenceScope reconciled =
                                            DexCfgObfuscatorPlugin.mergePriorStringEvidence(project,
                                                    stringEvidenceFile, stringDigest,
                                                    Collections.emptySet(), Collections.emptySet(),
                                                    activeOriginalClasses, Collections.emptyMap(),
                                                    Collections.emptyMap(), Collections.emptyMap(),
                                                    ext.stringEncryption.maxUnsafeSkippedStrings,
                                                    ext.stringEncryption.maxFilteredStrings,
                                                    variantName, 'application DEX',
                                                    fullCoverageProven)
                                    currentStringEvidence = true
                                    if (priorEvidence.isPresent()) {
                                        stringStats = priorEvidence.get().getStats()
                                    } else {
                                        snapshot.applyTo(stringStats)
                                    }
                                    DexCfgObfuscatorPlugin.applyReconciledStringScopeStats(
                                            stringStats, reconciled, project,
                                            fullCoverageProven)
                                    plaintextHashes = reconciled.plaintextHashes
                                    plaintextHashesByOriginalClass =
                                            reconciled.plaintextHashesByOriginalClass
                                    plaintextHashesByOriginalMethod =
                                            reconciled.plaintextHashesByOriginalMethod
                                    plaintextHashesByOriginalField =
                                            reconciled.plaintextHashesByOriginalField
                                    DexCfgObfuscatorPlugin.applyStringConfigurationToStats(
                                            ext.stringEncryption, stringStats,
                                            failOnUnknownCoverage)
                                    stringStats.artifactFingerprint = auditFingerprint
                                    stringStats.stringTransformDigest = stringDigest
                                    stringStats.evidenceSource = priorEvidence.isPresent()
                                            ? 'RECONCILED_INCREMENTAL' : 'CURRENT_BUILD'
                                    if (ext.stringEncryption.verifyFinalDex) {
                                        FinalStringScope applicationFinalScope =
                                                DexCfgObfuscatorPlugin.resolveFinalStringScope(
                                                        plaintextHashes,
                                                        plaintextHashesByOriginalClass,
                                                        plaintextHashesByOriginalMethod,
                                                        plaintextHashesByOriginalField,
                                                        useR8Mapping, r8MappingFile, variantName)
                                        DexCfgObfuscatorPlugin.applyFinalStringClassificationStats(
                                                applicationFinalScope, stringStats)
                                    }
                                    ObfuscatorStats evidenceStats =
                                            BuildEvidenceStore.snapshotStats(stringStats)
                                    DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                                            ext.stringEncryption, stringStats, variantName,
                                            failOnUnknownCoverage)
                                    StringEvidenceScope aggregateScope =
                                            DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(
                                                    project, dependencyEvidenceProjects,
                                                    variantName, variantCap, reconciled,
                                                    stringStats, failOnUnknownCoverage,
                                                    ext.stringEncryption.maxUnsafeSkippedStrings,
                                                    ext.stringEncryption.maxFilteredStrings)
                                    plaintextHashes = aggregateScope.plaintextHashes
                                    plaintextHashesByOriginalClass =
                                            aggregateScope.plaintextHashesByOriginalClass
                                    plaintextHashesByOriginalMethod =
                                            aggregateScope.plaintextHashesByOriginalMethod
                                    plaintextHashesByOriginalField =
                                            aggregateScope.plaintextHashesByOriginalField
                                    DexCfgObfuscatorPlugin.resetStringVerificationStats(
                                            stringStats, plaintextHashes.size())
                                    DexCfgObfuscatorPlugin.verifyFinalDexStrings(
                                            ext.stringEncryption, plaintextHashes,
                                            plaintextHashesByOriginalClass,
                                            plaintextHashesByOriginalMethod,
                                            plaintextHashesByOriginalField, stringAuditDexDirs,
                                            stringStats, variantName, project, useR8Mapping,
                                            r8MappingFile)
                                    DexCfgObfuscatorPlugin.failOnPlaintextLeakIfConfigured(
                                            ext.stringEncryption, stringStats, variantName)
                                    try {
                                        BuildEvidenceStore.writeString(stringEvidenceFile,
                                                auditFingerprint, stringDigest, evidenceStats,
                                                reconciled.plaintextHashes,
                                                reconciled.plaintextHashesByOriginalClass,
                                                reconciled.plaintextHashesByOriginalMethod,
                                                reconciled.plaintextHashesByOriginalField)
                                    } catch (Exception evidenceFailure) {
                                        throw new GradleException("[dex-cfg-obf] ${variantName}: " +
                                                "cannot rebind verified incremental string " +
                                                "evidence", evidenceFailure)
                                    }
                                    project.logger.lifecycle(priorEvidence.isPresent()
                                            ? "[dex-cfg-obf] ${variantName}: reconciled prior " +
                                            "string evidence with the current AGP scoped class " +
                                            "inventory and rebound it after the final DEX " +
                                            "plaintext gate"
                                            : "[dex-cfg-obf] ${variantName}: verified and bound " +
                                            "an empty full-build string scope after the final DEX " +
                                            "plaintext gate")
                                }
                            } else {
                                currentStringEvidence = true
                                snapshot.applyTo(stringStats)
                                if (!fullCoverageProven) {
                                    stringStats.stringCoverageStatus = 'PARTIAL_OR_FULL'
                                }
                                StringEvidenceScope scope =
                                        DexCfgObfuscatorPlugin.mergePriorStringEvidence(project,
                                        stringEvidenceFile, stringDigest,
                                        snapshot.encryptedPlaintextHashes,
                                        snapshot.visitedOriginalClassNames,
                                        activeOriginalClasses,
                                        snapshot.encryptedPlaintextHashesByOriginalClass,
                                        snapshot.encryptedPlaintextHashesByOriginalMethod,
                                        snapshot.encryptedPlaintextHashesByOriginalField,
                                        ext.stringEncryption.maxUnsafeSkippedStrings,
                                        ext.stringEncryption.maxFilteredStrings,
                                        variantName, 'application DEX',
                                        fullCoverageProven)
                                plaintextHashes = scope.plaintextHashes
                                plaintextHashesByOriginalClass =
                                        scope.plaintextHashesByOriginalClass
                                plaintextHashesByOriginalMethod =
                                        scope.plaintextHashesByOriginalMethod
                                plaintextHashesByOriginalField =
                                        scope.plaintextHashesByOriginalField
                                DexCfgObfuscatorPlugin.applyStringConfigurationToStats(
                                        ext.stringEncryption, stringStats, failOnUnknownCoverage)
                                stringStats.artifactFingerprint = auditFingerprint
                                stringStats.stringTransformDigest = stringDigest
                                stringStats.evidenceSource = 'CURRENT_BUILD'
                                if (ext.stringEncryption.verifyFinalDex) {
                                    FinalStringScope applicationFinalScope =
                                            DexCfgObfuscatorPlugin.resolveFinalStringScope(
                                                    plaintextHashes,
                                                    plaintextHashesByOriginalClass,
                                                    plaintextHashesByOriginalMethod,
                                                    plaintextHashesByOriginalField,
                                                    useR8Mapping, r8MappingFile, variantName)
                                    DexCfgObfuscatorPlugin.applyFinalStringClassificationStats(
                                            applicationFinalScope, stringStats)
                                }
                                ObfuscatorStats evidenceStats =
                                        BuildEvidenceStore.snapshotStats(stringStats)
                                // Enforce the application transform before dependency evidence is
                                // merged, otherwise library counts could mask a local regression.
                                DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                                        ext.stringEncryption,
                                        stringStats, variantName, failOnUnknownCoverage)
                                StringEvidenceScope aggregateScope =
                                        DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(project,
                                                dependencyEvidenceProjects, variantName, variantCap,
                                                new StringEvidenceScope(plaintextHashes,
                                                        plaintextHashesByOriginalClass,
                                                        plaintextHashesByOriginalMethod,
                                                        plaintextHashesByOriginalField), stringStats,
                                                failOnUnknownCoverage,
                                                ext.stringEncryption.maxUnsafeSkippedStrings,
                                                ext.stringEncryption.maxFilteredStrings)
                                plaintextHashes = aggregateScope.plaintextHashes
                                plaintextHashesByOriginalClass =
                                        aggregateScope.plaintextHashesByOriginalClass
                                plaintextHashesByOriginalMethod =
                                        aggregateScope.plaintextHashesByOriginalMethod
                                plaintextHashesByOriginalField =
                                        aggregateScope.plaintextHashesByOriginalField
                                DexCfgObfuscatorPlugin.resetStringVerificationStats(
                                        stringStats, plaintextHashes.size())
                                DexCfgObfuscatorPlugin.verifyFinalDexStrings(
                                        ext.stringEncryption, plaintextHashes,
                                        plaintextHashesByOriginalClass,
                                        plaintextHashesByOriginalMethod,
                                        plaintextHashesByOriginalField, stringAuditDexDirs,
                                        stringStats, variantName, project, useR8Mapping,
                                        r8MappingFile)
                                DexCfgObfuscatorPlugin.failOnPlaintextLeakIfConfigured(
                                        ext.stringEncryption, stringStats, variantName)
                                try {
                                    BuildEvidenceStore.writeString(stringEvidenceFile,
                                            auditFingerprint, stringDigest, evidenceStats,
                                            scope.plaintextHashes,
                                            scope.plaintextHashesByOriginalClass,
                                            scope.plaintextHashesByOriginalMethod,
                                            scope.plaintextHashesByOriginalField)
                                } catch (Exception evidenceFailure) {
                                    throw new GradleException("[dex-cfg-obf] ${variantName}: cannot " +
                                            "persist verified string evidence; refusing an " +
                                            "incrementally unverifiable artifact", evidenceFailure)
                                }
                                project.logger.lifecycle("[dex-cfg-obf] ${variantName}: encrypted " +
                                        "${snapshot.constantsEncrypted} string constant(s) in " +
                                        "${snapshot.classesModified} class(es), mode=${snapshot.mode}, " +
                                        "identityCiphertexts=${snapshot.identityCiphertexts}")
                            }
                            combinedStats.mergeFrom(stringStats)
                        }
                        combinedStats.cfgResolvedClassWideOwners =
                                config.resolvedClassWideIncludeClasses.size()
                        combinedStats.cfgResolvedMemberOnlyOwners =
                                config.resolvedIncludeClasses.count {
                                    !config.resolvedClassWideIncludeClasses.contains(it)
                                }
                        combinedStats.cfgResolvedMemberMethods =
                                config.resolvedIncludeMethods.size()
                        combinedStats.cfgRequiredMethodsResolved =
                                config.requiredResolvedIncludeMethods.size()
                        DexCfgObfuscatorPlugin.applyVariantStringConfigurationToStats(
                                stringRegistryKey != null, ext.stringEncryption,
                                combinedStats, failOnUnknownCoverage)
                        try {
                            combinedStats.artifactFingerprint =
                                    DexCfgObfuscatorPlugin.fingerprintDexDirectories(
                                    stringRegistryKey == null ? dexDirs : stringAuditDexDirs)
                        } catch (Exception fingerprintFailure) {
                            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot bind " +
                                    "the report to final DEX inputs", fingerprintFailure)
                        }
                        combinedStats.cfgTransformDigest = cfgDigest
                        if (combinedStats.stringTransformDigest == null
                                || combinedStats.stringTransformDigest.isEmpty()) {
                            combinedStats.stringTransformDigest = stringDigest
                        }
                        boolean anyCurrentEvidence = processedDexDirs > 0 || currentStringEvidence
                        boolean anyRestoredEvidence = skippedDexDirs > 0 || restoredStringEvidence
                        combinedStats.evidenceSource =
                                DexCfgObfuscatorPlugin.combinedEvidenceSource(anyCurrentEvidence,
                                        anyRestoredEvidence, missingStringEvidence)
                        if (reportFile != null) {
                            ObfuscationReportWriter.write(reportFile, variantName, config, combinedStats)
                            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: report ${reportFile}")
                        }
                        // Fresh and restored directories share one variant-level quality gate. Keeping
                        // budgets outside the per-directory transformer makes multi-output builds additive
                        // and guarantees the current schema report is written before a threshold failure.
                        DexCfgObfuscatorPlugin.enforceCfgQuality(
                                config, combinedStats, variantName)
                        DexCfgObfuscatorPlugin.enforceVariantStringGates(
                                stringRegistryKey != null, ext.stringEncryption, config,
                                combinedStats, variantName, failOnUnknownCoverage)
                        if (cfg.adversarialCommands != null &&
                                !cfg.adversarialCommands.isEmpty()) {
                            if (reportFile == null || !reportFile.isFile()) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: adversarialCommands " +
                                        "requires an existing report; run a pristine build first")
                            }
                            // 即使 CFG 目录指纹未变化，也必须重新运行刚配置或更新的 JADX/恢复器。
                            DexCfgObfuscatorPlugin.runAdversarialCommands(
                                    cfg.adversarialCommands, dexDirs, reportFile, variantName,
                                    cfg.adversarialTimeoutSeconds, project)
                        }
                        transactionFreshDexDirs.each { String canonicalDir ->
                            File freshDir = dexDirs.find { File candidate ->
                                candidate.canonicalPath == canonicalDir
                            }
                            if (freshDir == null) {
                                throw new GradleException("[dex-cfg-obf] ${variantName}: cannot " +
                                        "resolve fresh transaction directory ${canonicalDir}")
                            }
                            java.nio.file.Files.deleteIfExists(
                                    BuildEvidenceStore.cfgPendingFile(evidenceRoot, freshDir)
                                            .toPath())
                        }
                        project.logger.lifecycle("[dex-cfg-obf] ${variantName}: artifact contains " +
                                "${totalObf} obfuscated method(s); processedDexDirs=${processedDexDirs}, " +
                                "restoredEvidenceDirs=${skippedDexDirs}")
                            artifactTransaction.commit()
                        } catch (Throwable pipelineFailure) {
                            artifactPipelineFailure = pipelineFailure
                            if (artifactTransaction != null) {
                                try {
                                    artifactTransaction.rollback()
                                } catch (Throwable rollbackFailure) {
                                    pipelineFailure.addSuppressed(rollbackFailure)
                                }
                            }
                            throw pipelineFailure
                        } finally {
                            if (artifactTransaction != null) {
                                try {
                                    artifactTransaction.close()
                                } catch (Throwable closeFailure) {
                                    if (artifactPipelineFailure != null) {
                                        artifactPipelineFailure.addSuppressed(closeFailure)
                                    } else {
                                        throw new GradleException("[dex-cfg-obf] ${variantName}: " +
                                                'cannot close the variant artifact transaction',
                                                closeFailure)
                                    }
                                }
                            }
                        }
                    }
                }

                // Stack traces must be decoded with the exact mapping produced for this variant.
                // The task deliberately does not depend on obfTask: crash triage must never rebuild
                // or mutate application artifacts, and a current rebuild is not proof that its
                // mapping matches an already released APK. Build first, or pass an archived mapping.
                project.tasks.register(
                        "retrace${variantCap}DexCfgStackTrace",
                        RetraceDexCfgStackTraceTask) { RetraceDexCfgStackTraceTask task ->
                    task.group = 'obfuscation'
                    task.description = "Retrace a local ${variantName} crash stack-trace file " +
                            'with CFG-preserved positions and the matching R8 mapping.'
                    task.minified.set(useR8Mapping)
                    if (useR8Mapping) {
                        task.mappingFile.set(mappingProvider)
                    }
                    Object android = project.extensions.findByName('android')
                    File sdkDirectory = android != null && android.hasProperty('sdkDirectory')
                            ? android.sdkDirectory : null
                    if (sdkDirectory != null && sdkDirectory.isDirectory()) {
                        task.androidSdkDirectory.set(sdkDirectory)
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

    /** CFG 关闭时仍在最终 application DEX 上执行字符串明文门禁并产出报告。 */
    private static void registerStringOnlyVerificationTask(Project project,
                                                           def variant,
                                                           DexCfgObfuscatorExtension ext,
                                                           String variantName,
                                                           String variantCap,
                                                           String registryKey,
                                                           TaskProvider<StringClassInventoryTask>
                                                                   stringClassInventory,
                                                           List<String> dependencyEvidenceProjects,
                                                           boolean failOnUnknownCoverage) {
        String r8Name = "minify${variantCap}WithR8"
        String mergeProjName = "mergeProjectDex${variantCap}"
        String mergeDexName = "mergeDex${variantCap}"
        String mergeExtDexName = "mergeExtDex${variantCap}"
        String mergeLibDexName = "mergeLibDex${variantCap}"
        final boolean useR8 = variant.minifyEnabled
        def mappingProvider = useR8
                ? variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE.INSTANCE)
                : null
        TaskProvider<Task> verification = project.tasks.register(
                "verify${variantCap}DexStringEncryption") { Task task ->
            task.group = 'verification'
            task.description = "Verify ${variantName} final DEX does not retain encrypted plaintext."
            task.outputs.upToDateWhen { false }
            task.dependsOn(stringClassInventory)
            DexCfgObfuscatorPlugin.configureDependencyEvidenceTaskDependencies(task, project,
                    dependencyEvidenceProjects, variantCap)
            task.dependsOn({ ignored -> DexCfgObfuscatorPlugin.requirePrimaryDexProducer(
                    project, useR8, r8Name, mergeProjName, mergeDexName, variantName) })
            if (!useR8) {
                task.dependsOn(project.tasks.matching {
                    it.name == mergeExtDexName || it.name == mergeLibDexName
                            || it.name == "generate${variantCap}GlobalSynthetics"
                })
            }
            task.doLast {
                Task producer = DexCfgObfuscatorPlugin.requirePrimaryDexProducer(
                        project, useR8, r8Name, mergeProjName, mergeDexName, variantName)
                List<File> dexDirs = DexCfgObfuscatorPlugin.findDexDirectories(
                        project, variantName, producer)
                if (dexDirs.isEmpty()) {
                    throw new GradleException("[dex-cfg-obf] no dex output dir found for " +
                            "${variantName} (producer=${producer.name})")
                }
                List<File> stringAuditDexDirs =
                        DexCfgObfuscatorPlugin.findStringAuditDexDirectories(
                                project, variantCap, dexDirs, useR8)
                File r8MappingFile = null
                if (useR8) {
                    try {
                        r8MappingFile = mappingProvider?.get()?.asFile
                    } catch (Throwable ignored) {
                        // Fall through to the bounded conventional/output lookup.
                    }
                    if (r8MappingFile == null || !r8MappingFile.isFile()) {
                        r8MappingFile = DexCfgObfuscatorPlugin.findR8Mapping(
                                project, variantName, producer)
                    }
                    if (r8MappingFile == null || !r8MappingFile.isFile()) {
                        throw new GradleException("[dex-cfg-obf] ${variantName}: R8 mapping.txt " +
                                "not found for exact string owner scoping")
                    }
                }

                StringEncryptionSnapshot snapshot = StringEncryptionRegistry.snapshot(registryKey)
                File evidenceRoot = new File(project.buildDir,
                        "intermediates/dex-cfg-obfuscator-evidence/${variantName}")
                File evidenceFile = BuildEvidenceStore.stringEvidenceFile(evidenceRoot, variantName)
                String stringDigest = DexCfgObfuscatorPlugin.configurationDigest(
                        STRING_EVIDENCE_DIGEST_VERSION, registryKey)
                String auditFingerprint
                try {
                    auditFingerprint = DexCfgObfuscatorPlugin
                            .fingerprintDexDirectories(stringAuditDexDirs)
                } catch (Exception fingerprintFailure) {
                    throw new GradleException("[dex-cfg-obf] ${variantName}: cannot fingerprint " +
                            "all DEX inputs for string verification", fingerprintFailure)
                }
                ObfuscatorStats stats = new ObfuscatorStats()
                Set<String> plaintextHashes = Collections.emptySet()
                Map<String, Set<String>> plaintextHashesByOriginalClass =
                        Collections.emptyMap()
                Map<String, Set<String>> plaintextHashesByOriginalMethod =
                        Collections.emptyMap()
                Map<String, Set<String>> plaintextHashesByOriginalField =
                        Collections.emptyMap()
                String evidenceSource = 'MISSING'
                Set<String> activeOriginalClasses =
                        DexCfgObfuscatorPlugin.readStringClassInventory(
                                stringClassInventory, variantName)
                boolean fullCoverageProven =
                        DexCfgObfuscatorPlugin.proveCurrentStringCoverage(
                                project, registryKey, snapshot, activeOriginalClasses,
                                variantName, failOnUnknownCoverage)
                if (snapshot.classesVisited == 0) {
                    Optional<BuildEvidenceStore.StringEvidence> evidence
                    try {
                        evidence = BuildEvidenceStore.readString(evidenceFile,
                                auditFingerprint, stringDigest)
                    } catch (Exception evidenceFailure) {
                        throw new GradleException("[dex-cfg-obf] ${variantName}: string verification " +
                                "evidence is corrupt/unreadable; run a clean --rerun-tasks build",
                                evidenceFailure)
                    }
                    if (evidence.isPresent()) {
                        evidenceSource = 'CACHED_VERIFIED'
                        DexCfgObfuscatorPlugin.requireStringOwnerScope(
                                evidence.get(), variantName, 'application DEX')
                        DexCfgObfuscatorPlugin.requireStringSkipReasonStats(evidence.get(),
                                ext.stringEncryption.maxUnsafeSkippedStrings,
                                ext.stringEncryption.maxFilteredStrings,
                                variantName, 'application DEX')
                        stats = evidence.get().getStats()
                        plaintextHashes = evidence.get().getPlaintextSha256()
                        plaintextHashesByOriginalClass =
                                evidence.get().getPlaintextSha256ByOriginalClass()
                        plaintextHashesByOriginalMethod =
                                evidence.get().getPlaintextSha256ByOriginalMethod()
                        plaintextHashesByOriginalField =
                                evidence.get().getPlaintextSha256ByOriginalField()
                        stats.stringCoverageStatus = DexCfgObfuscatorPlugin.
                                restoredApplicationStringCoverageStatus(
                                        project, evidence.get().getCoverageStatus())
                        // Keep application quality thresholds local; dependency evidence is
                        // aggregated only for the final APK plaintext gate and report.
                        DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                                ext.stringEncryption, stats, variantName,
                                failOnUnknownCoverage)
                        StringEvidenceScope aggregateScope =
                                DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(
                                project, dependencyEvidenceProjects, variantName, variantCap,
                                new StringEvidenceScope(plaintextHashes,
                                        plaintextHashesByOriginalClass,
                                        plaintextHashesByOriginalMethod,
                                        plaintextHashesByOriginalField), stats,
                                failOnUnknownCoverage,
                                ext.stringEncryption.maxUnsafeSkippedStrings,
                                ext.stringEncryption.maxFilteredStrings)
                        plaintextHashes = aggregateScope.plaintextHashes
                        plaintextHashesByOriginalClass =
                                aggregateScope.plaintextHashesByOriginalClass
                        plaintextHashesByOriginalMethod =
                                aggregateScope.plaintextHashesByOriginalMethod
                        plaintextHashesByOriginalField =
                                aggregateScope.plaintextHashesByOriginalField
                        DexCfgObfuscatorPlugin.resetStringVerificationStats(
                                stats, plaintextHashes.size())
                        DexCfgObfuscatorPlugin.verifyFinalDexStrings(
                                ext.stringEncryption, plaintextHashes,
                                plaintextHashesByOriginalClass,
                                plaintextHashesByOriginalMethod,
                                plaintextHashesByOriginalField, stringAuditDexDirs, stats,
                                variantName, project, useR8, r8MappingFile)
                        project.logger.lifecycle("[dex-cfg-obf] ${variantName}: restored string " +
                                "evidence bound to the current DEX artifact; " +
                                "coverage=${stats.stringCoverageStatus}")
                    } else {
                        Optional<BuildEvidenceStore.StringEvidence> priorEvidence
                        try {
                            priorEvidence = BuildEvidenceStore.readString(evidenceFile)
                        } catch (Exception evidenceFailure) {
                            throw new GradleException("[dex-cfg-obf] ${variantName}: prior string " +
                                    "evidence is corrupt/unreadable; run a clean --rerun-tasks " +
                                    "build", evidenceFailure)
                        }
                        boolean verifiedEmptyFullBuild = !priorEvidence.isPresent() &&
                                fullCoverageProven
                        if (!priorEvidence.isPresent() && !verifiedEmptyFullBuild) {
                            throw new GradleException("[dex-cfg-obf] ${variantName}: no prior " +
                                    "string evidence is available for the changed final DEX; " +
                                    "run clean with --rerun-tasks")
                        }
                        DexCfgObfuscatorPlugin.
                                requireExecutedAsmTransformForZeroVisitReconciliation(
                                        project, variantCap, variantName)
                        StringEvidenceScope reconciled =
                                DexCfgObfuscatorPlugin.mergePriorStringEvidence(project,
                                        evidenceFile, stringDigest, Collections.emptySet(),
                                        Collections.emptySet(), activeOriginalClasses,
                                        Collections.emptyMap(), Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        ext.stringEncryption.maxUnsafeSkippedStrings,
                                        ext.stringEncryption.maxFilteredStrings,
                                        variantName, 'application DEX',
                                        fullCoverageProven)
                        evidenceSource = priorEvidence.isPresent()
                                ? 'RECONCILED_INCREMENTAL' : 'CURRENT_BUILD'
                        if (priorEvidence.isPresent()) {
                            stats = priorEvidence.get().getStats()
                        } else {
                            snapshot.applyTo(stats)
                        }
                        DexCfgObfuscatorPlugin.applyReconciledStringScopeStats(
                                stats, reconciled, project, fullCoverageProven)
                        plaintextHashes = reconciled.plaintextHashes
                        plaintextHashesByOriginalClass =
                                reconciled.plaintextHashesByOriginalClass
                        plaintextHashesByOriginalMethod =
                                reconciled.plaintextHashesByOriginalMethod
                        plaintextHashesByOriginalField =
                                reconciled.plaintextHashesByOriginalField
                        DexCfgObfuscatorPlugin.applyStringConfigurationToStats(
                                ext.stringEncryption, stats, failOnUnknownCoverage)
                        stats.artifactFingerprint = auditFingerprint
                        stats.stringTransformDigest = stringDigest
                        stats.evidenceSource = evidenceSource
                        ObfuscatorStats evidenceStats = BuildEvidenceStore.snapshotStats(stats)
                        DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                                ext.stringEncryption, stats, variantName,
                                failOnUnknownCoverage)
                        StringEvidenceScope aggregateScope =
                                DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(
                                        project, dependencyEvidenceProjects, variantName,
                                        variantCap, reconciled, stats, failOnUnknownCoverage,
                                        ext.stringEncryption.maxUnsafeSkippedStrings,
                                        ext.stringEncryption.maxFilteredStrings)
                        plaintextHashes = aggregateScope.plaintextHashes
                        plaintextHashesByOriginalClass =
                                aggregateScope.plaintextHashesByOriginalClass
                        plaintextHashesByOriginalMethod =
                                aggregateScope.plaintextHashesByOriginalMethod
                        plaintextHashesByOriginalField =
                                aggregateScope.plaintextHashesByOriginalField
                        DexCfgObfuscatorPlugin.resetStringVerificationStats(
                                stats, plaintextHashes.size())
                        DexCfgObfuscatorPlugin.verifyFinalDexStrings(
                                ext.stringEncryption, plaintextHashes,
                                plaintextHashesByOriginalClass,
                                plaintextHashesByOriginalMethod,
                                plaintextHashesByOriginalField, stringAuditDexDirs, stats,
                                variantName, project, useR8, r8MappingFile)
                        DexCfgObfuscatorPlugin.failOnPlaintextLeakIfConfigured(
                                ext.stringEncryption, stats, variantName)
                        try {
                            BuildEvidenceStore.writeString(evidenceFile, auditFingerprint,
                                    stringDigest, evidenceStats, reconciled.plaintextHashes,
                                    reconciled.plaintextHashesByOriginalClass,
                                    reconciled.plaintextHashesByOriginalMethod,
                                    reconciled.plaintextHashesByOriginalField)
                        } catch (Exception evidenceFailure) {
                            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot " +
                                    "rebind verified incremental string evidence", evidenceFailure)
                        }
                        project.logger.lifecycle(priorEvidence.isPresent()
                                ? "[dex-cfg-obf] ${variantName}: reconciled prior string " +
                                "evidence with the current AGP scoped class inventory and rebound " +
                                "it after the final DEX plaintext gate"
                                : "[dex-cfg-obf] ${variantName}: verified and bound an empty " +
                                "full-build string scope after the final DEX plaintext gate")
                    }
                } else {
                    evidenceSource = 'CURRENT_BUILD'
                    snapshot.applyTo(stats)
                    if (!fullCoverageProven) {
                        stats.stringCoverageStatus = 'PARTIAL_OR_FULL'
                    }
                    StringEvidenceScope scope = DexCfgObfuscatorPlugin.mergePriorStringEvidence(
                            project, evidenceFile,
                            stringDigest, snapshot.encryptedPlaintextHashes,
                            snapshot.visitedOriginalClassNames,
                            activeOriginalClasses,
                            snapshot.encryptedPlaintextHashesByOriginalClass,
                            snapshot.encryptedPlaintextHashesByOriginalMethod,
                            snapshot.encryptedPlaintextHashesByOriginalField,
                            ext.stringEncryption.maxUnsafeSkippedStrings,
                            ext.stringEncryption.maxFilteredStrings,
                            variantName, 'application DEX', fullCoverageProven)
                    plaintextHashes = scope.plaintextHashes
                    plaintextHashesByOriginalClass = scope.plaintextHashesByOriginalClass
                    plaintextHashesByOriginalMethod = scope.plaintextHashesByOriginalMethod
                    plaintextHashesByOriginalField = scope.plaintextHashesByOriginalField
                    DexCfgObfuscatorPlugin.applyStringConfigurationToStats(
                            ext.stringEncryption, stats, failOnUnknownCoverage)
                    stats.artifactFingerprint = auditFingerprint
                    stats.stringTransformDigest = stringDigest
                    stats.evidenceSource = evidenceSource
                    ObfuscatorStats evidenceStats = BuildEvidenceStore.snapshotStats(stats)
                    DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                            ext.stringEncryption, stats, variantName, failOnUnknownCoverage)
                    StringEvidenceScope aggregateScope =
                            DexCfgObfuscatorPlugin.mergeDependencyStringEvidence(project,
                            dependencyEvidenceProjects, variantName, variantCap,
                            new StringEvidenceScope(plaintextHashes,
                                    plaintextHashesByOriginalClass,
                                    plaintextHashesByOriginalMethod,
                                    plaintextHashesByOriginalField), stats,
                            failOnUnknownCoverage,
                            ext.stringEncryption.maxUnsafeSkippedStrings,
                            ext.stringEncryption.maxFilteredStrings)
                    plaintextHashes = aggregateScope.plaintextHashes
                    plaintextHashesByOriginalClass =
                            aggregateScope.plaintextHashesByOriginalClass
                    plaintextHashesByOriginalMethod =
                            aggregateScope.plaintextHashesByOriginalMethod
                    plaintextHashesByOriginalField =
                            aggregateScope.plaintextHashesByOriginalField
                    DexCfgObfuscatorPlugin.resetStringVerificationStats(
                            stats, plaintextHashes.size())
                    DexCfgObfuscatorPlugin.verifyFinalDexStrings(
                            ext.stringEncryption, plaintextHashes,
                            plaintextHashesByOriginalClass,
                            plaintextHashesByOriginalMethod,
                            plaintextHashesByOriginalField, stringAuditDexDirs, stats,
                            variantName, project, useR8, r8MappingFile)
                    DexCfgObfuscatorPlugin.failOnPlaintextLeakIfConfigured(
                            ext.stringEncryption, stats, variantName)
                    try {
                        BuildEvidenceStore.writeString(evidenceFile, auditFingerprint,
                                stringDigest, evidenceStats, scope.plaintextHashes,
                                scope.plaintextHashesByOriginalClass,
                                scope.plaintextHashesByOriginalMethod,
                                scope.plaintextHashesByOriginalField)
                    } catch (Exception evidenceFailure) {
                        throw new GradleException("[dex-cfg-obf] ${variantName}: cannot persist " +
                                "verified string evidence; refusing an incrementally " +
                                "unverifiable artifact", evidenceFailure)
                    }
                }
                DexCfgObfuscatorPlugin.applyStringConfigurationToStats(
                        ext.stringEncryption, stats, failOnUnknownCoverage)
                stats.artifactFingerprint = auditFingerprint
                if (stats.stringTransformDigest == null
                        || stats.stringTransformDigest.isEmpty()) {
                    stats.stringTransformDigest = stringDigest
                }
                stats.evidenceSource = evidenceSource

                // CFG 模块关闭时，字符串报告不继承任何 CFG 运行配置。
                ObfuscatorConfig reportConfig = new ObfuscatorConfig()
                reportConfig.depth = 0
                File reportFile = new File(project.buildDir,
                        "reports/dex-cfg-obfuscator/${variantName}.json")
                ObfuscationReportWriter.write(reportFile, variantName, reportConfig, stats)
                project.logger.lifecycle("[dex-cfg-obf] ${variantName}: string verification report " +
                        "${reportFile}")
                DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                        ext.stringEncryption, stats, variantName, failOnUnknownCoverage)
                DexCfgObfuscatorPlugin.failOnPlaintextLeakIfConfigured(
                        ext.stringEncryption, stats, variantName)
            }
        }
        project.tasks.matching {
            it.name == "package${variantCap}" || it.name == "merge${variantCap}Assets"
        }.configureEach { it.dependsOn verification }
    }

    /** Published AARs expose JVM constant pools, so remove plaintext entries made unreachable by ASM. */
    private void registerLibraryConstantPoolCompaction(Project project,
                                                        String variantName,
                                                        String variantCap,
                                                        String registryKey,
                                                        TaskProvider<StringClassInventoryTask>
                                                                stringClassInventory,
                                                        StringEncryptionExtension strings,
                                                        boolean variantMinified,
                                                        boolean failOnUnknownCoverage) {
        String transformTaskName = "transform${variantCap}ClassesWithAsm"
        def transforms = project.tasks.matching { it.name == transformTaskName }
        File evidenceRoot = new File(project.buildDir,
                "intermediates/dex-cfg-obfuscator-evidence/${variantName}/library")
        File evidenceFile = BuildEvidenceStore.stringEvidenceFile(evidenceRoot,
                variantName + '-library-class-pool')
        String canonicalBuildDirDigest = configurationDigest('library-build-lock-v1',
                project.buildDir.canonicalPath)
        // Never place this inode below buildDir: another process running clean could unlink it.
        // Anchoring beside buildDir also makes different root projects sharing that exact buildDir
        // resolve the same lock pathname.
        File buildLockFile = new File(project.buildDir.parentFile,
                ".gradle/dex-cfg-obfuscator-locks/${canonicalBuildDirDigest}.lock")
        if (registeredLibraryLockReleases.add(canonicalBuildDirDigest)) {
            LibraryBuildLock.registerRelease(flowScope, flowProviders,
                    canonicalBuildDirDigest)
        }

        // Acquire before clean can delete shared outputs and before the standard Android build
        // graph starts producing them. The Flow release runs only after all scheduled build work.
        project.tasks.matching {
            it.name == 'clean' || it.name == 'preBuild' ||
                    it.name == "pre${variantCap}Build"
        }.configureEach { Task earlyTask ->
            earlyTask.doFirst {
                LibraryBuildLock.acquire(canonicalBuildDirDigest, buildLockFile)
            }
        }

        // This action is part of the transform task itself so Gradle snapshots/caches the compacted
        // bytes. A separate downstream task mutating these outputs makes the transform rerun forever.
        transforms.configureEach { Task transform ->
            transform.doFirst {
                LibraryBuildLock.acquire(canonicalBuildDirDigest, buildLockFile)
            }
            transform.doLast {
                int compacted
                try {
                    compacted = StringClassConstantPoolCompactor.compactOutputs(
                            transform.outputs.files.files,
                            StringEncryptionRegistry.require(registryKey))
                } catch (Exception failure) {
                    throw new GradleException("[dex-cfg-obf] ${variantName}: cannot compact " +
                            "published library class constant pools", failure)
                }
                project.logger.lifecycle("[dex-cfg-obf] ${variantName}: compacted ${compacted} " +
                        "modified library class constant pool(s) inside ${transformTaskName}")
            }
        }

        TaskProvider<Task> compaction = project.tasks.register(
                "compact${variantCap}LibraryStringConstantPools") { Task task ->
            task.group = 'obfuscation'
            task.description = "Verify ${variantName} library class pools after string encryption."
            task.outputs.upToDateWhen { false }
            task.dependsOn(stringClassInventory)
            task.extensions.extraProperties.set(LIBRARY_EVIDENCE_MINIFIED_PROPERTY,
                    variantMinified)
            task.dependsOn(transforms)
            task.doFirst {
                LibraryBuildLock.acquire(canonicalBuildDirDigest, buildLockFile)
            }
            task.doLast {
                Set<Task> transformTasks = project.tasks.matching {
                    it.name == transformTaskName
                }.findAll()
                if (transformTasks.isEmpty()) {
                    throw new GradleException("[dex-cfg-obf] ${variantName}: library ASM " +
                            "transform task ${transformTaskName} not found")
                }
                LinkedHashSet<File> outputs = new LinkedHashSet<>()
                transformTasks.each { Task transform ->
                    outputs.addAll(transform.outputs.files.files)
                }
                Set<String> requiredDecryptorMethods =
                        DexCfgObfuscatorPlugin.discoverRequiredDecryptorOriginalMethods(
                                project, variantCap, variantName, registryKey)
                String stringDigest = DexCfgObfuscatorPlugin.configurationDigest(
                        LIBRARY_STRING_EVIDENCE_DIGEST_VERSION, registryKey,
                        requiredDecryptorMethods)
                // Publish metadata only from this successful artifact inspection. Configuration-
                // time candidates are intentionally forbidden because they overstate unused bridge
                // overloads and become stale when the ASM task is restored from cache.
                task.extensions.extraProperties.set(LIBRARY_EVIDENCE_DIGEST_PROPERTY,
                        stringDigest)
                task.extensions.extraProperties.set(
                        LIBRARY_REQUIRED_DECRYPTOR_METHODS_PROPERTY,
                        requiredDecryptorMethods)
                StringEncryptionSnapshot snapshot = StringEncryptionRegistry.snapshot(registryKey)
                String fingerprint
                try {
                    // The transform's doLast action owns the only output mutation. Keeping this
                    // downstream task read-only prevents app R8/merge consumers (which also depend
                    // on the transform output) from racing a second in-place compaction pass. Cache
                    // hits already restore the post-doLast bytes and are accepted only with exact
                    // fingerprint/configuration evidence below.
                    fingerprint = StringClassConstantPoolCompactor.fingerprintOutputs(outputs)
                } catch (Exception failure) {
                    throw new GradleException("[dex-cfg-obf] ${variantName}: cannot fingerprint " +
                            "published library class constant pools", failure)
                }

                ObfuscatorStats stats = new ObfuscatorStats()
                Set<String> plaintextHashes = Collections.emptySet()
                Map<String, Set<String>> plaintextHashesByOriginalClass =
                        Collections.emptyMap()
                Map<String, Set<String>> plaintextHashesByOriginalMethod =
                        Collections.emptyMap()
                Map<String, Set<String>> plaintextHashesByOriginalField =
                        Collections.emptyMap()
                String evidenceSource
                Set<String> activeOriginalClasses =
                        DexCfgObfuscatorPlugin.readStringClassInventory(
                                stringClassInventory, variantName)
                boolean fullCoverageProven =
                        DexCfgObfuscatorPlugin.proveCurrentStringCoverage(
                                project, registryKey, snapshot, activeOriginalClasses,
                                variantName, failOnUnknownCoverage)
                if (snapshot.classesVisited == 0) {
                    Optional<BuildEvidenceStore.StringEvidence> evidence
                    try {
                        evidence = BuildEvidenceStore.readString(evidenceFile, fingerprint,
                                stringDigest)
                    } catch (Exception evidenceFailure) {
                        throw new GradleException("[dex-cfg-obf] ${variantName}: library string " +
                                "evidence is corrupt/unreadable; run clean with --rerun-tasks",
                                evidenceFailure)
                    }
                    if (evidence.isPresent()) {
                        evidenceSource = 'CACHED_VERIFIED'
                        DexCfgObfuscatorPlugin.requireStringOwnerScope(
                                evidence.get(), variantName, 'library')
                        DexCfgObfuscatorPlugin.requireStringSkipReasonStats(evidence.get(),
                                strings.maxUnsafeSkippedStrings, strings.maxFilteredStrings,
                                variantName, 'library')
                        stats = evidence.get().getStats()
                        plaintextHashes = evidence.get().getPlaintextSha256()
                        plaintextHashesByOriginalClass =
                                evidence.get().getPlaintextSha256ByOriginalClass()
                        plaintextHashesByOriginalMethod =
                                evidence.get().getPlaintextSha256ByOriginalMethod()
                        plaintextHashesByOriginalField =
                                evidence.get().getPlaintextSha256ByOriginalField()
                        stats.stringCoverageStatus =
                                DexCfgObfuscatorPlugin.isTrustedFullCoverage(
                                        evidence.get().getCoverageStatus())
                                ? 'CACHED_FULL' : 'CACHED_PARTIAL'
                    } else if (fullCoverageProven) {
                        evidenceSource = 'CURRENT_BUILD'
                        snapshot.applyTo(stats)
                    } else {
                        evidenceSource = 'MISSING'
                        stats.stringEncryptionEnabled = true
                        stats.stringEncryptionMode = snapshot.mode
                        stats.stringCoverageStatus = 'UNKNOWN_INCREMENTAL'
                        if (strings.failOnPlaintextLeak) {
                            throw new GradleException("[dex-cfg-obf] ${variantName}: no library " +
                                    "string evidence matches the current class artifact; run clean " +
                                    "with --rerun-tasks before publishing the AAR")
                        }
                    }
                } else {
                    evidenceSource = 'CURRENT_BUILD'
                    snapshot.applyTo(stats)
                    if (!fullCoverageProven) {
                        stats.stringCoverageStatus = 'PARTIAL_OR_FULL'
                    }
                    StringEvidenceScope scope = DexCfgObfuscatorPlugin.mergePriorStringEvidence(
                            project, evidenceFile,
                            stringDigest, snapshot.encryptedPlaintextHashes,
                            snapshot.visitedOriginalClassNames,
                            activeOriginalClasses,
                            snapshot.encryptedPlaintextHashesByOriginalClass,
                            snapshot.encryptedPlaintextHashesByOriginalMethod,
                            snapshot.encryptedPlaintextHashesByOriginalField,
                            strings.maxUnsafeSkippedStrings,
                            strings.maxFilteredStrings,
                            variantName, 'library', fullCoverageProven)
                    plaintextHashes = scope.plaintextHashes
                    plaintextHashesByOriginalClass = scope.plaintextHashesByOriginalClass
                    plaintextHashesByOriginalMethod = scope.plaintextHashesByOriginalMethod
                    plaintextHashesByOriginalField = scope.plaintextHashesByOriginalField
                }

                StringClassConstantPoolCompactor.VerificationResult verification
                try {
                    verification = StringClassConstantPoolCompactor.verifyNoPlaintext(outputs,
                            plaintextHashes, strings.strictWholeStringPool)
                } catch (Exception verificationFailure) {
                    throw new GradleException("[dex-cfg-obf] ${variantName}: cannot verify " +
                            "pre-packaging library JVM constant pools", verificationFailure)
                }
                DexCfgObfuscatorPlugin.applyLibraryStringVerificationStats(verification, stats)
                stats.artifactFingerprint = fingerprint
                stats.stringTransformDigest = stringDigest
                stats.evidenceSource = evidenceSource
                DexCfgObfuscatorPlugin.applyStringConfigurationToStats(
                        strings, stats, failOnUnknownCoverage)
                if (stats.stringConstantsEncrypted > 0 && requiredDecryptorMethods.isEmpty()) {
                    throw new GradleException("[dex-cfg-obf] ${variantName}: library evidence " +
                            "records ${stats.stringConstantsEncrypted} encrypted string(s), but " +
                            'the current ASM artifact exposes no generated decryptor call')
                }

                if (verification.plaintextLeaks > 0) {
                    String leakMessage = "[dex-cfg-obf] ${variantName}: pre-packaging library " +
                            "plaintext gate found ${verification.plaintextLeaks} protected value(s) " +
                            "in ${verification.plaintextLeakOccurrences} " +
                            "${verification.strictWholeStringPool ? 'whole-pool' : 'runtime payload'} " +
                            "occurrence(s); values and hashes are not logged"
                    if (strings.failOnPlaintextLeak) throw new GradleException(leakMessage)
                    project.logger.warn(leakMessage + '; continuing after warning-only verification')
                }
                if (snapshot.classesVisited > 0) {
                    try {
                        BuildEvidenceStore.writeString(evidenceFile, fingerprint, stringDigest,
                                stats, plaintextHashes, plaintextHashesByOriginalClass,
                                plaintextHashesByOriginalMethod,
                                plaintextHashesByOriginalField)
                    } catch (Exception evidenceFailure) {
                        throw new GradleException("[dex-cfg-obf] ${variantName}: cannot persist " +
                                "library string verification evidence", evidenceFailure)
                    }
                }
                DexCfgObfuscatorPlugin.failOnStringQualityIfConfigured(
                        strings, stats, variantName, failOnUnknownCoverage)
                String verificationSummary = "${verification.classesScanned} class(es), " +
                        "${verification.utf8EntriesScanned} JVM UTF8 entries, " +
                        "${verification.plaintextHashesTracked} protected value(s), " +
                        "mode=${verification.strictWholeStringPool ? 'STRICT_WHOLE_POOL' : 'RUNTIME_PAYLOAD'}, " +
                        "${verification.ldcStringValuesScanned} LDC String value(s), " +
                        "${verification.staticStringValuesScanned} static String value(s), " +
                        "${verification.annotationStringValuesScanned} annotation String value(s), " +
                        "${verification.callSiteStringValuesScanned} call-site String value(s), " +
                        "${verification.wholePoolPlaintextCollisions} whole-pool collision(s) in " +
                        "${verification.wholePoolPlaintextCollisionOccurrences} pool occurrence(s), " +
                        "evidence=${evidenceSource}"
                if (verification.plaintextLeaks == 0 && evidenceSource != 'MISSING') {
                    project.logger.lifecycle("[dex-cfg-obf] ${variantName}: pre-packaging library " +
                            "class-pool plaintext gate passed (${verificationSummary})")
                } else if (evidenceSource == 'MISSING') {
                    project.logger.warn("[dex-cfg-obf] ${variantName}: pre-packaging library " +
                            "class-pool plaintext gate has no matching evidence " +
                            "(${verificationSummary})")
                }
            }
        }
        project.tasks.matching {
            it.name == "sync${variantCap}LibJars" || it.name == "bundle${variantCap}Aar"
        }.configureEach {
            it.dependsOn compaction
            it.doFirst {
                LibraryBuildLock.acquire(canonicalBuildDirDigest, buildLockFile)
            }
        }
    }

    private static void verifyFinalDexStrings(StringEncryptionExtension strings,
                                              Set<String> plaintextHashes,
                                              Map<String, ? extends Set<String>>
                                                      plaintextHashesByOriginalClass,
                                              Map<String, ? extends Set<String>>
                                                      plaintextHashesByOriginalMethod,
                                              Map<String, ? extends Set<String>>
                                                      plaintextHashesByOriginalField,
                                              List<File> dexDirs,
                                              ObfuscatorStats stats,
                                              String variantName,
                                              Project project,
                                              boolean useR8Mapping,
                                              File r8MappingFile) {
        if (!strings.verifyFinalDex) return
        FinalStringScope finalScope = resolveFinalStringScope(plaintextHashes,
                plaintextHashesByOriginalClass, plaintextHashesByOriginalMethod,
                plaintextHashesByOriginalField, useR8Mapping, r8MappingFile, variantName)
        StringPlaintextVerifier.Result result = StringPlaintextVerifier.verifyDexDirectories(
                dexDirs, plaintextHashes, finalScope.plaintextHashesByFinalClass,
                finalScope.plaintextHashesByFinalMethod,
                finalScope.plaintextHashesByFinalField,
                finalScope.globalRuntimeFallbackHashes,
                finalScope.removedOriginalSiteHashes,
                finalScope.identityFieldProvenanceTargets,
                strings.strictWholeStringPool)
        if (result.targetClassesScanned != result.targetClassesResolved
                || result.targetMethodsScanned != result.targetMethodsResolved
                || result.targetFieldsScanned != result.targetFieldsResolved
                || result.identityFieldProvenanceScanned
                != result.identityFieldProvenanceResolved) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: final DEX plaintext gate " +
                    "scanned ${result.targetClassesScanned}/${result.targetClassesResolved} " +
                    "target class(es), ${result.targetMethodsScanned}/" +
                    "${result.targetMethodsResolved} target method(s), and " +
                    "${result.targetFieldsScanned}/${result.targetFieldsResolved} target " +
                    "field(s), plus ${result.identityFieldProvenanceScanned}/" +
                    "${result.identityFieldProvenanceResolved} identity field provenance " +
                    "target(s); dependency/application evidence is not fully present in the " +
                    "final artifact")
        }
        stats.stringPlaintextVerified = true
        stats.stringDexFilesScanned = result.dexFilesScanned
        stats.stringPoolEntriesScanned = result.stringPoolEntriesScanned
        stats.stringPlaintextHashesTracked = result.plaintextHashesTracked
        stats.stringPlaintextGateMode = result.strictWholeStringPool
                ? 'STRICT_WHOLE_POOL'
                : (result.globalRuntimeFallbackHashesTracked > 0
                ? 'RUNTIME_PAYLOAD_EXACT_WITH_GLOBAL_FALLBACK' : 'RUNTIME_PAYLOAD')
        stats.stringPlaintextLeaks = result.plaintextLeaks
        stats.stringPlaintextLeakOccurrences = result.plaintextLeakOccurrences
        stats.stringRuntimePlaintextLeaks = result.runtimePlaintextLeaks
        stats.stringRuntimePlaintextLeakOccurrences = result.runtimePlaintextLeakOccurrences
        stats.stringScopedRuntimePlaintextLeaks = result.scopedRuntimePlaintextLeaks
        stats.stringScopedRuntimePlaintextLeakOccurrences =
                result.scopedRuntimePlaintextLeakOccurrences
        stats.stringGlobalRuntimeFallbackHashesTracked =
                result.globalRuntimeFallbackHashesTracked
        stats.stringGlobalRuntimeFallbackPlaintextLeaks =
                result.globalRuntimeFallbackPlaintextLeaks
        stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences =
                result.globalRuntimeFallbackPlaintextLeakOccurrences
        stats.stringOwnerRuntimePlaintextCollisions =
                result.ownerRuntimePlaintextCollisions
        stats.stringOwnerRuntimePlaintextCollisionOccurrences =
                result.ownerRuntimePlaintextCollisionOccurrences
        stats.stringGlobalRuntimePlaintextCollisions = result.globalRuntimePlaintextCollisions
        stats.stringGlobalRuntimePlaintextCollisionOccurrences =
                result.globalRuntimePlaintextCollisionOccurrences
        stats.stringWholePoolPlaintextCollisions = result.wholePoolPlaintextCollisions
        stats.stringWholePoolPlaintextCollisionOccurrences =
                result.wholePoolPlaintextCollisionOccurrences
        stats.stringTargetClassesResolved = result.targetClassesResolved
        stats.stringTargetClassesScanned = result.targetClassesScanned
        stats.stringTargetMethodsResolved = result.targetMethodsResolved
        stats.stringTargetMethodsScanned = result.targetMethodsScanned
        stats.stringTargetFieldsResolved = result.targetFieldsResolved
        stats.stringTargetFieldsScanned = result.targetFieldsScanned
        applyFinalStringClassificationStats(finalScope, stats)
        stats.stringRemovedOriginalSiteHashesTracked =
                result.removedOriginalSiteHashesTracked
        stats.stringIdentityFieldProvenanceResolved =
                result.identityFieldProvenanceResolved
        stats.stringIdentityFieldProvenanceScanned =
                result.identityFieldProvenanceScanned
        stats.stringConstStringReferencesScanned = result.constStringReferencesScanned
        stats.stringStaticStringValuesScanned = result.staticStringValuesScanned
        stats.stringAnnotationStringValuesScanned = result.annotationStringValuesScanned
        stats.stringCallSiteStringValuesScanned = result.callSiteStringValuesScanned
        stats.stringStructuralAnnotationStringValuesScanned =
                result.structuralAnnotationStringValuesScanned
        stats.stringStructuralAnnotationPlaintextCollisions =
                result.structuralAnnotationPlaintextCollisions
        stats.stringStructuralAnnotationPlaintextCollisionOccurrences =
                result.structuralAnnotationPlaintextCollisionOccurrences
        String scanSummary = "${result.constStringReferencesScanned} const-string reference(s), " +
                "${result.staticStringValuesScanned} static String value(s), " +
                "${result.annotationStringValuesScanned} annotation String value(s), " +
                "${result.callSiteStringValuesScanned} call-site String value(s), " +
                "${result.targetClassesScanned}/${result.targetClassesResolved} target class(es), " +
                "${result.targetMethodsScanned}/${result.targetMethodsResolved} target method(s), " +
                "${result.targetFieldsScanned}/${result.targetFieldsResolved} target field(s), " +
                "${result.identityFieldProvenanceScanned}/" +
                "${result.identityFieldProvenanceResolved} identity field provenance target(s), " +
                "${result.removedOriginalSiteHashesTracked} removed-site hash(es), " +
                "R8 method classes [mapped=${finalScope.r8MappedMethodSites}, " +
                "removed=${finalScope.r8RemovedMethodSites}, " +
                "identity=${finalScope.r8IdentityMethodSites}, " +
                "fallback=${finalScope.r8FallbackMethodSites}], " +
                "R8 field provenance [mapped=${finalScope.r8MappedFieldProvenance}, " +
                "removed=${finalScope.r8RemovedFieldProvenance}, " +
                "identity=${finalScope.r8IdentityFieldProvenance}, " +
                "fallback=${finalScope.r8FallbackFieldProvenance}], " +
                "${result.globalRuntimeFallbackHashesTracked} global runtime fallback hash(es), " +
                "${result.globalRuntimeFallbackPlaintextLeaks} fallback leak(s) in " +
                "${result.globalRuntimeFallbackPlaintextLeakOccurrences} occurrence(s), " +
                "${result.ownerRuntimePlaintextCollisions} target-owner collision(s) in " +
                "${result.ownerRuntimePlaintextCollisionOccurrences} occurrence(s), " +
                "${result.globalRuntimePlaintextCollisions} global runtime collision(s) in " +
                "${result.globalRuntimePlaintextCollisionOccurrences} occurrence(s), " +
                "${result.wholePoolPlaintextCollisions} whole-pool collision(s) in " +
                "${result.wholePoolPlaintextCollisionOccurrences} pool occurrence(s)"
        if (result.plaintextLeaks == 0) {
            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: final DEX plaintext gate passed " +
                    "(${result.plaintextHashesTracked} unique encrypted value(s), " +
                    "mode=${stats.stringPlaintextGateMode}, " +
                    "${result.stringPoolEntriesScanned} string-pool entries, ${scanSummary})")
        } else {
            project.logger.warn("[dex-cfg-obf] ${variantName}: final DEX plaintext gate found " +
                    "${result.plaintextLeaks} leaked encrypted value(s) in " +
                    "${result.plaintextLeakOccurrences} " +
                    "${result.strictWholeStringPool ? 'whole-pool occurrence(s)' : 'runtime payload occurrence(s)'}; " +
                    "${scanSummary}; values and hashes are not logged")
        }
    }

    private static void applyFinalStringClassificationStats(
            FinalStringScope finalScope, ObfuscatorStats stats) {
        stats.stringR8MappedMethodSites = finalScope.r8MappedMethodSites
        stats.stringR8RemovedMethodSites = finalScope.r8RemovedMethodSites
        stats.stringR8IdentityMethodSites = finalScope.r8IdentityMethodSites
        stats.stringR8FallbackMethodSites = finalScope.r8FallbackMethodSites
        stats.stringR8MappedFieldProvenance = finalScope.r8MappedFieldProvenance
        stats.stringR8RemovedFieldProvenance = finalScope.r8RemovedFieldProvenance
        stats.stringR8IdentityFieldProvenance = finalScope.r8IdentityFieldProvenance
        stats.stringR8FallbackFieldProvenance = finalScope.r8FallbackFieldProvenance
        stats.stringRemovedOriginalSiteHashesTracked =
                finalScope.removedOriginalSiteHashes.size()
        stats.stringIdentityFieldProvenanceResolved =
                finalScope.identityFieldProvenanceTargets.size()
        stats.stringIdentityFieldProvenanceScanned = 0
    }

    static void applyLibraryStringVerificationStats(
            StringClassConstantPoolCompactor.VerificationResult verification,
            ObfuscatorStats stats) {
        stats.stringPlaintextVerified = true
        stats.stringDexFilesScanned = 0
        stats.stringPoolEntriesScanned = verification.utf8EntriesScanned
        stats.stringPlaintextHashesTracked = verification.plaintextHashesTracked
        stats.stringPlaintextGateMode = verification.strictWholeStringPool
                ? 'LIBRARY_JVM_STRICT_WHOLE_POOL' : 'LIBRARY_JVM_RUNTIME_PAYLOAD'
        stats.stringPlaintextLeaks = verification.plaintextLeaks
        stats.stringPlaintextLeakOccurrences = verification.plaintextLeakOccurrences
        stats.stringRuntimePlaintextLeaks = verification.runtimePlaintextLeaks
        stats.stringRuntimePlaintextLeakOccurrences =
                verification.runtimePlaintextLeakOccurrences
        stats.stringGlobalRuntimePlaintextCollisions = verification.runtimePlaintextLeaks
        stats.stringGlobalRuntimePlaintextCollisionOccurrences =
                verification.runtimePlaintextLeakOccurrences
        stats.stringWholePoolPlaintextCollisions = verification.wholePoolPlaintextCollisions
        stats.stringWholePoolPlaintextCollisionOccurrences =
                verification.wholePoolPlaintextCollisionOccurrences
        stats.stringConstStringReferencesScanned = verification.ldcStringValuesScanned
        stats.stringStaticStringValuesScanned = verification.staticStringValuesScanned
        stats.stringAnnotationStringValuesScanned = verification.annotationStringValuesScanned
        stats.stringCallSiteStringValuesScanned = verification.callSiteStringValuesScanned
    }

    private static void failOnPlaintextLeakIfConfigured(StringEncryptionExtension strings,
                                                         ObfuscatorStats stats,
                                                         String variantName) {
        if (strings.verifyFinalDex && strings.failOnPlaintextLeak) {
            if (!stats.stringPlaintextVerified) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: final DEX plaintext gate " +
                        "has no evidence bound to the current artifact/configuration; run clean " +
                        "with --rerun-tasks")
            }
            if (stats.stringPlaintextLeaks > 0) {
                String scope = strings.strictWholeStringPool
                        ? 'whole-string-pool plaintext collision(s) under strict mode'
                        : (stats.stringGlobalRuntimeFallbackHashesTracked > 0
                        ? 'exact-site/global-fallback runtime-readable plaintext payload(s)'
                        : 'site-scoped runtime-readable plaintext payload(s)')
                throw new GradleException("[dex-cfg-obf] ${variantName}: final DEX contains " +
                        "${stats.stringPlaintextLeaks} ${scope} selected for encryption; " +
                        "see the report for gate counts (values and hashes are intentionally omitted)")
            }
        }
    }

    /**
     * Apply final application string gates only when this exact variant registered the string
     * transform. The extension object is shared by every variant, so neither the global switch nor
     * the selector alone can describe whether this exact variant registered the stage.
     */
    static void enforceVariantStringGates(boolean stringStageEnabled,
                                          StringEncryptionExtension strings,
                                          ObfuscatorConfig config,
                                          ObfuscatorStats stats,
                                          String variantName,
                                          boolean failOnUnknownCoverage) {
        if (!stringStageEnabled) return
        enforceRequiredDecryptorCfg(strings, config, stats, variantName)
        failOnStringQualityIfConfigured(
                strings, stats, variantName, failOnUnknownCoverage)
        failOnPlaintextLeakIfConfigured(strings, stats, variantName)
    }

    private static void failOnStringQualityIfConfigured(StringEncryptionExtension strings,
                                                         ObfuscatorStats stats,
                                                         String variantName) {
        failOnStringQualityIfConfigured(strings, stats, variantName,
                strings.failOnUnknownCoverage)
    }

    private static void failOnStringQualityIfConfigured(StringEncryptionExtension strings,
                                                         ObfuscatorStats stats,
                                                         String variantName,
                                                         boolean failOnUnknownCoverage) {
        if (!isTrustedFullCoverage(stats.stringCoverageStatus)) {
            if (failOnUnknownCoverage) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: string coverage status is " +
                        "${stats.stringCoverageStatus}; run clean with --rerun-tasks to enforce full coverage")
            }
            return
        }
        if (stats.stringConstantsEncrypted < strings.minEncryptedStrings) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: encrypted string count " +
                    "${stats.stringConstantsEncrypted} is below minEncryptedStrings=" +
                    "${strings.minEncryptedStrings}")
        }
        if (stats.stringClassesModified < strings.minModifiedClasses) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: modified string class count " +
                    "${stats.stringClassesModified} is below minModifiedClasses=" +
                    "${strings.minModifiedClasses}")
        }
        if (stats.stringConstantsSkipped > strings.maxSkippedStrings) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: skipped string count " +
                    "${stats.stringConstantsSkipped} exceeds maxSkippedStrings=" +
                    "${strings.maxSkippedStrings}")
        }
        int unsafeSkipped = stats.stringSkippedTooLarge + stats.stringSkippedInvalidUnicode
        if (unsafeSkipped > strings.maxUnsafeSkippedStrings) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: unsafe skipped string " +
                    "count ${unsafeSkipped} (tooLarge=${stats.stringSkippedTooLarge}, " +
                    "invalidUnicode=${stats.stringSkippedInvalidUnicode}) exceeds " +
                    "maxUnsafeSkippedStrings=${strings.maxUnsafeSkippedStrings}")
        }
        if (stats.stringSkippedFiltered > strings.maxFilteredStrings) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: custom-filtered string count " +
                    "${stats.stringSkippedFiltered} exceeds maxFilteredStrings=" +
                    "${strings.maxFilteredStrings}")
        }
    }

    private static void applyStringConfigurationToStats(StringEncryptionExtension strings,
                                                         ObfuscatorStats stats) {
        applyStringConfigurationToStats(strings, stats, strings.failOnUnknownCoverage)
    }

    private static void applyStringConfigurationToStats(StringEncryptionExtension strings,
                                                         ObfuscatorStats stats,
                                                         boolean failOnUnknownCoverage) {
        stats.stringMinEncryptedStrings = strings.minEncryptedStrings
        stats.stringMinModifiedClasses = strings.minModifiedClasses
        stats.stringMaxSkippedStrings = strings.maxSkippedStrings
        stats.stringMaxUnsafeSkippedStrings = strings.maxUnsafeSkippedStrings
        stats.stringMaxFilteredStrings = strings.maxFilteredStrings
        stats.stringFailOnUnknownCoverage = failOnUnknownCoverage
        stats.stringVerifyFinalDex = strings.verifyFinalDex
        stats.stringFailOnPlaintextLeak = strings.failOnPlaintextLeak
        if (!stats.stringPlaintextVerified) {
            stats.stringPlaintextGateMode = strings.verifyFinalDex
                    ? (strings.strictWholeStringPool ? 'STRICT_WHOLE_POOL' : 'RUNTIME_PAYLOAD')
                    : 'DISABLED'
        }
        stats.stringFailOnUnsupportedConstants = strings.failOnUnsupportedStringConstants
        stats.stringFailOnUnprotectedDecryptor = strings.failOnUnprotectedDecryptor
    }

    /** Keep a CFG-only variant's report in the DISABLED string state. */
    static void applyVariantStringConfigurationToStats(boolean stringStageEnabled,
                                                       StringEncryptionExtension strings,
                                                       ObfuscatorStats stats,
                                                       boolean failOnUnknownCoverage) {
        if (!stringStageEnabled) return
        applyStringConfigurationToStats(strings, stats, failOnUnknownCoverage)
    }

    private static boolean isTrustedFullCoverage(String status) {
        return 'FULL'.equals(status) || 'CACHED_FULL'.equals(status)
    }

    /** A base-APK evidence snapshot cannot prove coverage for newly present feature-split DEX. */
    static String restoredApplicationStringCoverageStatus(Project project,
                                                          String evidenceCoverageStatus) {
        return isTrustedFullCoverage(evidenceCoverageStatus) && !hasDynamicFeatures(project)
                ? 'CACHED_FULL' : 'CACHED_PARTIAL'
    }

    private static String weakestStringCoverage(String first, String second) {
        if (!isTrustedFullCoverage(first)) return first
        if (!isTrustedFullCoverage(second)) {
            return 'CACHED_PARTIAL'.equals(second) ? 'CACHED_PARTIAL' : 'PARTIAL_OR_FULL'
        }
        return first
    }

    static void resetStringVerificationStats(ObfuscatorStats stats, int trackedHashes) {
        stats.stringPlaintextVerified = false
        stats.stringDexFilesScanned = 0
        stats.stringPoolEntriesScanned = 0
        stats.stringPlaintextHashesTracked = trackedHashes
        stats.stringPlaintextGateMode = 'DISABLED'
        stats.stringPlaintextLeaks = 0
        stats.stringPlaintextLeakOccurrences = 0
        stats.stringRuntimePlaintextLeaks = 0
        stats.stringRuntimePlaintextLeakOccurrences = 0
        stats.stringScopedRuntimePlaintextLeaks = 0
        stats.stringScopedRuntimePlaintextLeakOccurrences = 0
        stats.stringGlobalRuntimeFallbackHashesTracked = 0
        stats.stringGlobalRuntimeFallbackPlaintextLeaks = 0
        stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = 0
        stats.stringOwnerRuntimePlaintextCollisions = 0
        stats.stringOwnerRuntimePlaintextCollisionOccurrences = 0
        stats.stringGlobalRuntimePlaintextCollisions = 0
        stats.stringGlobalRuntimePlaintextCollisionOccurrences = 0
        stats.stringWholePoolPlaintextCollisions = 0
        stats.stringWholePoolPlaintextCollisionOccurrences = 0
        stats.stringTargetClassesResolved = 0
        stats.stringTargetClassesScanned = 0
        stats.stringTargetMethodsResolved = 0
        stats.stringTargetMethodsScanned = 0
        stats.stringTargetFieldsResolved = 0
        stats.stringTargetFieldsScanned = 0
        stats.stringR8MappedMethodSites = 0
        stats.stringR8RemovedMethodSites = 0
        stats.stringR8IdentityMethodSites = 0
        stats.stringR8FallbackMethodSites = 0
        stats.stringR8MappedFieldProvenance = 0
        stats.stringR8RemovedFieldProvenance = 0
        stats.stringR8IdentityFieldProvenance = 0
        stats.stringR8FallbackFieldProvenance = 0
        stats.stringRemovedOriginalSiteHashesTracked = 0
        stats.stringIdentityFieldProvenanceResolved = 0
        stats.stringIdentityFieldProvenanceScanned = 0
        stats.stringConstStringReferencesScanned = 0
        stats.stringStaticStringValuesScanned = 0
        stats.stringAnnotationStringValuesScanned = 0
        stats.stringCallSiteStringValuesScanned = 0
        stats.stringStructuralAnnotationStringValuesScanned = 0
        stats.stringStructuralAnnotationPlaintextCollisions = 0
        stats.stringStructuralAnnotationPlaintextCollisionOccurrences = 0
    }

    private static void enforceCfgQuality(ObfuscatorConfig config,
                                          ObfuscatorStats stats,
                                          String variantName) {
        if (stats.methodsObfuscated < config.minObfuscatedMethods) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: aggregate CFG statistics have " +
                    "${stats.methodsObfuscated} obfuscated method(s), below " +
                    "minObfuscatedMethods=${config.minObfuscatedMethods}")
        }
        if (stats.methodsFlattened < config.minFlattenedMethods) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: aggregate CFG statistics have " +
                    "${stats.methodsFlattened} flattened method(s), below " +
                    "minFlattenedMethods=${config.minFlattenedMethods}")
        }
        if (stats.obfuscatedRatio() + 1.0e-12d < config.minObfuscatedRatio) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: aggregate CFG statistics have " +
                    "obfuscated ratio ${stats.obfuscatedRatio()}, below " +
                    "minObfuscatedRatio=${config.minObfuscatedRatio}")
        }
        if (stats.sizeIncreasePercent() > config.maxSizeIncreasePercent) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: aggregate CFG statistics have " +
                    "size increase ${stats.sizeIncreasePercent()}%, above " +
                    "maxSizeIncreasePercent=${config.maxSizeIncreasePercent}")
        }
    }

    static void configureRequiredDecryptorMethods(
            ObfuscatorConfig config,
            Collection<String> requiredOriginalMethodKeys,
            boolean useR8Mapping,
            File r8MappingFile,
            String variantName) {
        Set<String> originalMethods = new TreeSet<>()
        (requiredOriginalMethodKeys ?: Collections.emptySet()).each { String method ->
            originalMethods.add(normalizeRequiredDecryptorMethodKey(method, variantName))
        }
        if (originalMethods.isEmpty()) {
            // String protection may be enabled with a zero minimum and legitimately find no sites.
            // In that case there is no reachable runtime decryptor to protect. The final stats gate
            // below still rejects encrypted evidence paired with an empty runtime call scope.
            return
        }
        TreeSet<String> requiredFinalMethods = new TreeSet<>()
        if (useR8Mapping) {
            R8MappingResolver.ExactMemberResolution resolution
            try {
                resolution = R8MappingResolver.resolveExactMembers(r8MappingFile,
                        originalMethods, Collections.emptySet())
            } catch (Exception mappingFailure) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: cannot resolve generated " +
                        "decryptor methods through R8 mapping", mappingFailure)
            }
            if (!resolution.isComplete()) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: R8 mapping resolved " +
                        "${resolution.getResolvedMethodCount()} of ${originalMethods.size()} " +
                        "generated decryptor methods; refusing unprotected runtime decryption")
            }
            resolution.getResolvedMethods().values().each {
                Set<R8MappingResolver.FinalMember> targets ->
                    targets.each { R8MappingResolver.FinalMember target ->
                        String owner = target.getOwnerInternalName()
                        String finalKey = owner + '->' + target.getMemberName()
                        requiredFinalMethods.add(finalKey)
                        config.resolvedIncludeClasses.add(owner)
                        config.resolvedIncludeMethods.add(finalKey)
                    }
            }
        } else {
            originalMethods.each { String original ->
                int arrow = original.indexOf('->')
                int open = original.indexOf('(', arrow + 2)
                String finalKey = original.substring(0, arrow) + '->' +
                        original.substring(arrow + 2, open)
                requiredFinalMethods.add(finalKey)
                config.resolvedIncludeClasses.add(original.substring(0, arrow))
                config.resolvedIncludeMethods.add(finalKey)
            }
        }
        if (requiredFinalMethods.isEmpty()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: generated decryptor method " +
                    "scope resolved empty")
        }
        config.requiredResolvedIncludeMethods.addAll(requiredFinalMethods)
    }

    private static String normalizeRequiredDecryptorMethodKey(String raw, String variantName) {
        String value = raw == null ? '' : raw.trim()
        int arrow = value.indexOf('->')
        int open = value.indexOf('(', arrow + 2)
        int close = value.indexOf(')', open + 1)
        if (arrow <= 0 || value.indexOf('->', arrow + 2) >= 0 || open <= arrow + 2
                || close <= open || close >= value.length() - 1) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: invalid required decryptor " +
                    'original method key')
        }
        String owner = ObfuscatorConfig.normalizeClassName(value.substring(0, arrow))
        String memberAndDescriptor = value.substring(arrow + 2)
        if (owner.isEmpty() || owner.contains(' ') || owner.contains('#')
                || !memberAndDescriptor.startsWith('decrypt(')) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: invalid required decryptor " +
                    'original method key')
        }
        return owner + '->' + memberAndDescriptor
    }

    private static Set<String> collectRequiredDecryptorOriginalMethods(
            Project applicationProject,
            Collection<String> dependencyProjects,
            String variantCap,
            String variantName,
            Collection<String> applicationMethods) {
        TreeSet<String> methods = new TreeSet<>()
        (applicationMethods ?: Collections.emptySet()).each { String method ->
            methods.add(normalizeRequiredDecryptorMethodKey(method, variantName))
        }
        (dependencyProjects ?: Collections.emptyList()).each { String path ->
            Project dependencyProject = applicationProject.rootProject.findProject(path)
            String taskName = "compact${variantCap}LibraryStringConstantPools"
            Task task = dependencyProject?.tasks?.findByName(taskName)
            if (task == null || !task.state.executed || task.state.skipped
                    || task.state.failure != null) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} " +
                        "required-decryptor metadata task ${taskName} did not complete successfully")
            }
            def extra = task.extensions.extraProperties
            if (!extra.has(LIBRARY_REQUIRED_DECRYPTOR_METHODS_PROPERTY)) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} " +
                        "did not expose required decryptor original method keys")
            }
            Object raw = extra.get(LIBRARY_REQUIRED_DECRYPTOR_METHODS_PROPERTY)
            if (!(raw instanceof Collection)) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} " +
                        'required decryptor original method keys are missing/invalid')
            }
            ((Collection<?>) raw).each { Object method ->
                methods.add(normalizeRequiredDecryptorMethodKey(
                        method == null ? null : method.toString(), variantName))
            }
        }
        return Collections.unmodifiableSet(methods)
    }

    private static TaskProvider<StringClassInventoryTask> registerStringClassInventory(
            Project project,
            def variant,
            String variantName,
            String variantCap,
            def scope) {
        TaskProvider<StringClassInventoryTask> inventory = project.tasks.register(
                "inventory${variantCap}DexStringClasses", StringClassInventoryTask) { task ->
            task.group = 'verification'
            task.description = "Inventory ${variantName} pre-DEX class owners for string evidence."
            task.ownerInventoryFile.set(project.layout.buildDirectory.file(
                    "intermediates/dex-cfg-obfuscator-class-inventory/" +
                            "${variantName}/owners.txt"))
        }
        variant.artifacts.forScope(scope).use(inventory).toGet(
                ScopedArtifact.CLASSES.INSTANCE,
                { StringClassInventoryTask task -> task.inputJars },
                { StringClassInventoryTask task -> task.inputDirectories })
        return inventory
    }

    private static Set<String> readStringClassInventory(
            TaskProvider<StringClassInventoryTask> inventory,
            String variantName) {
        if (inventory == null) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: string class inventory " +
                    'task was not registered')
        }
        StringClassInventoryTask task = inventory.get()
        if (!task.state.executed || task.state.failure != null) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: string class inventory " +
                    'did not complete before evidence reconciliation')
        }
        try {
            return StringClassInventoryTask.readOwners(task.ownerInventoryFile.get().asFile)
        } catch (Exception failure) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot read the current " +
                    'AGP scoped-classes owner inventory', failure)
        }
    }

    /**
     * Derive required decryptor methods from the transformed class artifact, not transient visitor
     * state. The ASM task may be UP-TO-DATE or restored FROM-CACHE, in which case the current
     * registry context has observed no classes even though the artifact contains encrypted sites.
     */
    private static Set<String> discoverRequiredDecryptorOriginalMethods(
            Project project,
            String variantCap,
            String variantName,
            String registryKey) {
        LinkedHashSet<File> outputs = completedAsmTransformOutputs(
                project, variantCap, variantName, 'decryptor usage discovery')
        try {
            TreeSet<String> methods = new TreeSet<>(StringEncryptionRegistry.
                    requiredDecryptorOriginalMethodKeys(registryKey))
            methods.addAll(StringEncryptionRegistry.
                    discoverRequiredDecryptorOriginalMethodKeys(registryKey, outputs))
            return Collections.unmodifiableSet(methods)
        } catch (Exception failure) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot discover generated " +
                    'decryptor carrier usage from current ASM class outputs', failure)
        }
    }

    private static LinkedHashSet<File> completedAsmTransformOutputs(
            Project project,
            String variantCap,
            String variantName,
            String purpose) {
        String transformTaskName = "transform${variantCap}ClassesWithAsm"
        Set<Task> transforms = project.tasks.matching {
            it.name == transformTaskName
        }.findAll()
        if (transforms.size() != 1) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: expected exactly one " +
                    "${transformTaskName} task for ${purpose}, found " +
                    transforms.size())
        }
        Task transform = transforms.first()
        if (!transform.state.executed || transform.state.failure != null) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: ASM transform task " +
                    "${transformTaskName} did not complete before ${purpose}")
        }
        return new LinkedHashSet<>(transform.outputs.files.files)
    }

    static void enforceRequiredDecryptorCfg(
            StringEncryptionExtension strings,
            ObfuscatorConfig config,
            ObfuscatorStats stats,
            String variantName) {
        if (!strings.failOnUnprotectedDecryptor) return
        int required = config.requiredResolvedIncludeMethods.size()
        if (required == 0) {
            if (stats.stringConstantsEncrypted > 0) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: string evidence records " +
                        "${stats.stringConstantsEncrypted} encrypted string(s), but the current " +
                        'artifact exposes no generated decryptor call to protect')
            }
            return
        }
        if (stats.cfgRequiredMethodsScanned < required ||
                stats.cfgRequiredMethodsObfuscated != stats.cfgRequiredMethodsScanned ||
                !stats.hasCompleteRequiredMethodCoverage(
                        config.requiredResolvedIncludeMethods)) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: generated decryptor CFG " +
                    "coverage is incomplete (required=${required}, " +
                    "scanned=${stats.cfgRequiredMethodsScanned}, " +
                    "obfuscated=${stats.cfgRequiredMethodsObfuscated})")
        }
    }

    /** 记录用户是否显式要求 Gradle 重跑；严格 variant 还会通过 instrumentation nonce 自动强制全量。 */
    private static boolean isFullStringCoverageBuild(Project project) {
        return project.gradle.startParameter.rerunTasks
    }

    /**
     * A strict string gate must not require callers to know about --rerun-tasks. Its changing
     * instrumentation input forces AGP to execute a non-incremental ASM traversal for this variant.
     */
    static boolean isFullStringCoverageInvocation(Project project,
                                                  boolean forceFullCoverage) {
        return forceFullCoverage || isFullStringCoverageBuild(project)
    }

    static String fullCoverageInvocationNonce(Project project,
                                               boolean forceFullCoverage) {
        return isFullStringCoverageInvocation(project, forceFullCoverage)
                ? java.util.UUID.randomUUID().toString()
                : 'cacheable'
    }

    /**
     * The nonce requests a complete traversal; the scoped owner inventory proves that AGP actually
     * delivered every selected class before the result is allowed to claim FULL coverage.
     */
    private static boolean proveCurrentStringCoverage(Project project,
                                                      String registryKey,
                                                      StringEncryptionSnapshot snapshot,
                                                      Set<String> activeOriginalClasses,
                                                      String variantName,
                                                      boolean forceFullCoverage) {
        if (!isFullStringCoverageInvocation(project, forceFullCoverage)
                || hasDynamicFeatures(project)) {
            return false
        }
        StringEncryptionContext context = StringEncryptionRegistry.require(registryKey)
        boolean complete = hasCompleteVisitedStringCoverage(context,
                activeOriginalClasses, snapshot.visitedOriginalClassNames)
        int selectedOwners = countSelectedStringOwners(context, activeOriginalClasses)
        if (complete) {
            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: full string coverage " +
                    "proven by scoped class inventory (selected=${selectedOwners}, " +
                    "visited=${snapshot.visitedOriginalClassNames.size()})")
        } else {
            project.logger.warn("[dex-cfg-obf] ${variantName}: requested full string coverage " +
                    "but scoped class inventory does not match ASM visits (selected=" +
                    "${selectedOwners}, visited=${snapshot.visitedOriginalClassNames.size()}); " +
                    'keeping coverage fail-closed')
        }
        return complete
    }

    static boolean hasCompleteVisitedStringCoverage(StringEncryptionContext context,
                                                     Set<String> activeOriginalClasses,
                                                     Set<String> visitedOriginalClasses) {
        if (context == null) return false
        TreeSet<String> expected = new TreeSet<>()
        (activeOriginalClasses ?: Collections.emptySet()).each { String owner ->
            if (context.shouldVisitClass(owner)) {
                expected.add(ObfuscatorConfig.normalizeClassName(owner))
            }
        }
        TreeSet<String> visited = new TreeSet<>()
        (visitedOriginalClasses ?: Collections.emptySet()).each { String owner ->
            String normalized = ObfuscatorConfig.normalizeClassName(owner)
            if (!normalized.isEmpty()) visited.add(normalized)
        }
        return expected.equals(visited)
    }

    private static int countSelectedStringOwners(StringEncryptionContext context,
                                                 Set<String> activeOriginalClasses) {
        int count = 0
        (activeOriginalClasses ?: Collections.emptySet()).each { String owner ->
            if (context.shouldVisitClass(owner)) count++
        }
        return count
    }

    /**
     * A changed DEX with an empty in-process snapshot is safe to reconcile only when AGP actually
     * ran the ASM transform in this invocation. UP-TO-DATE/FROM-CACHE outputs can hide a changed
     * protected class whose new hashes were never observed by the visitor.
     */
    private static void requireExecutedAsmTransformForZeroVisitReconciliation(
            Project project,
            String variantCap,
            String variantName) {
        String transformTaskName = "transform${variantCap}ClassesWithAsm"
        Set<Task> transforms = project.tasks.matching {
            it.name == transformTaskName
        }.findAll()
        if (transforms.size() != 1) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot prove that the " +
                    "ASM string transform ran for zero-visit evidence reconciliation; expected " +
                    "exactly one ${transformTaskName} task, found ${transforms.size()}; run " +
                    'clean with --rerun-tasks')
        }
        Task transform = transforms.first()
        if (!transform.state.executed || transform.state.failure != null ||
                transform.state.skipped || !transform.state.didWork) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: changed final DEX has no " +
                    "current string visits, but ${transformTaskName} was skipped, cached, " +
                    'up-to-date, or otherwise did no work; run clean with --rerun-tasks')
        }
    }

    /** Reconciled evidence has owner/hash lower bounds, never trustworthy prior occurrence totals. */
    private static void applyReconciledStringScopeStats(
            ObfuscatorStats stats,
            StringEvidenceScope scope,
            Project project) {
        applyReconciledStringScopeStats(stats, scope, project,
                isFullStringCoverageBuild(project))
    }

    private static void applyReconciledStringScopeStats(
            ObfuscatorStats stats,
            StringEvidenceScope scope,
            Project project,
            boolean fullCurrentCoverage) {
        stats.stringClassesVisited = 0
        stats.stringClassesModified = scope.plaintextHashesByOriginalClass.size()
        stats.stringConstantsEncrypted = scope.plaintextHashes.size()
        if (fullCurrentCoverage) {
            // A zero-visit full rerun proves that no selected class contributed an occurrence.
            // Prior occurrence/skip counters are not owner-scoped and must not survive deletion of
            // the final protected owner.
            stats.stringConstantsSkipped = 0
            stats.stringSkippedWhitespace = 0
            stats.stringSkippedTooLarge = 0
            stats.stringSkippedInvalidUnicode = 0
            stats.stringSkippedFiltered = 0
            stats.stringUnsupportedConstants = 0
            stats.stringIdentityCiphertexts = 0
        }
        stats.stringCoverageStatus = fullCurrentCoverage
                ? 'FULL' : 'PARTIAL_OR_FULL'
    }

    private static String configureStringEncryption(Project project,
                                                     def variant,
                                                     DexCfgObfuscatorExtension ext,
                                                     String variantName,
                                                     String variantCap,
                                                     boolean cfgEnabled,
                                                     boolean includeDependencies,
                                                     boolean forceFullCoverage) {
        if (project.gradle.startParameter.configurationCacheRequested) {
            throw new GradleException('[dex-cfg-obf] stringEncryption does not yet support Gradle ' +
                    'configuration cache because custom cipher/key objects are build-process state; ' +
                    'rerun with --no-configuration-cache')
        }
        if (project.plugins.hasPlugin('stringfog')) {
            throw new GradleException('[dex-cfg-obf] built-in stringEncryption and the StringFog plugin ' +
                    'cannot be enabled together; remove id/apply plugin: stringfog first')
        }
        StringEncryptionExtension strings = ext.stringEncryption
        DexObfuscatorExtension cfg = ext.dexObfuscator
        validateStringQualityConfiguration(strings)
        // null 才表示继承。显式 [] 很重要：字符串覆盖面和 CFG 覆盖面可能不同，
        // 不能把 CFG 的 verifier/runtime 排除项静默套到字符串阶段。
        List<String> includes = strings.packages == null
                ? new ArrayList<>(cfg.obfClass ?: [])
                : new ArrayList<>(strings.packages)
        List<String> excludes = strings.excludePackages == null
                ? new ArrayList<>(cfg.blackClass ?: [])
                : new ArrayList<>(strings.excludePackages)

        // variant.namespace 是 finalize-on-read Provider，在 AGP 9 的 onVariants 回调中直接 get()
        // 仍可能早于 project configuration complete。BaseExtension 的已配置 DSL 值可安全读取。
        def androidExtension = project.extensions.findByName('android')
        if (project.plugins.hasPlugin('com.android.application')) {
            Collection<?> dynamicFeatures = []
            try {
                dynamicFeatures = new ArrayList<>(androidExtension?.dynamicFeatures ?: [])
            } catch (groovy.lang.MissingPropertyException ignored) {
                // Older AGP without dynamic-feature support has no split DEX boundary to inspect.
            }
            validateDynamicFeatureCoverage(dynamicFeatures, strings)
            if (!dynamicFeatures.isEmpty()) {
                project.logger.warn('[dex-cfg-obf] dynamicFeatures are present; string coverage ' +
                        'will remain partial because feature split DEX is not scanned')
            }
        }
        String namespace = androidExtension?.namespace
        String configuredBridge = strings.bridgeClass == null ? null : strings.bridgeClass.trim()
        if ((namespace == null || namespace.trim().isEmpty())
                && (configuredBridge == null || configuredBridge.isEmpty())) {
            throw new GradleException('[dex-cfg-obf] stringEncryption requires android.namespace ' +
                    'or an explicit stringEncryption.bridgeClass')
        }
        String bridgeClass = configuredBridge == null || configuredBridge.isEmpty()
                ? defaultBridgeClass(namespace, project.path)
                : configuredBridge
        if (strings.implementation != null
                && bridgeClass == strings.implementation.trim()) {
            throw new GradleException('[dex-cfg-obf] stringEncryption.bridgeClass must differ from ' +
                    'the runtime implementation class')
        }
        if (project.plugins.hasPlugin('com.android.application') && cfgEnabled) {
            warnIfDecryptorMissesCfg(project, cfg, strings, bridgeClass, 'generated bridge')
            if (strings.implementation != null && !strings.implementation.trim().isEmpty()) {
                warnIfDecryptorMissesCfg(project, cfg, strings, strings.implementation.trim(),
                        'custom implementation')
            }
        }
        StringEncryptionContext context = StringEncryptionContext.create(
                strings.algorithm,
                strings.implementation,
                strings.keyGenerator,
                includes,
                excludes,
                bridgeClass,
                strings.resolvedMode(),
                strings.seed,
                strings.maxStringBytes,
                strings.debug,
                strings.verifyRoundTrip,
                strings.allowIdentityCiphertext,
                strings.decryptorStatic,
                strings.failOnUnsupportedStringConstants)
        String registryKey = project.rootDir.canonicalPath + '|' + project.path + '|' + variantName +
                '|' + configurationDigest(strings.implementation,
                context.configurationFingerprint, strings.configurationId,
                strings.resolvedMode(), strings.seed, strings.maxStringBytes, bridgeClass,
                strings.decryptorStatic, strings.verifyRoundTrip,
                strings.allowIdentityCiphertext, strings.failOnUnsupportedStringConstants,
                includeDependencies ? 'ALL' : 'PROJECT', includes, excludes)
        StringEncryptionRegistry.register(registryKey, context)
        project.gradle.buildFinished { ignored -> StringEncryptionRegistry.remove(registryKey) }

        TaskProvider<GenerateStringDecryptorTask> generator = project.tasks.register(
                "generate${variantCap}DexStringDecryptor", GenerateStringDecryptorTask) { task ->
            task.group = 'obfuscation'
            task.description = "Generate ${variantName} runtime string decryptor."
            task.outputDirectory.set(project.layout.buildDirectory.dir(
                    "generated/source/dex-string-encryption/${variantName}"))
            task.bridgeClassName.set(bridgeClass)
            task.implementationClassName.set(strings.implementation ?: '')
            task.decryptorStatic.set(strings.decryptorStatic)
        }
        variant.sources.java.addGeneratedSourceDirectory(generator) { task -> task.outputDirectory }
        TaskProvider<GenerateStringProtectionRulesTask> rules = project.tasks.register(
                "generate${variantCap}DexStringProtectionRules",
                GenerateStringProtectionRulesTask) { task ->
            task.group = 'obfuscation'
            task.description = "Generate ${variantName} final-R8 string protection rules."
            task.outputFile.set(project.layout.buildDirectory.file(
                    "generated/dex-string-encryption/${variantName}/r8-rules.pro"))
            task.methodMarkerAnnotationClassName.set(
                    context.methodMarkerAnnotationClassName)
        }
        def ruleFile = rules.flatMap { task -> task.outputFile }
        wireStringProtectionRules(variant, ruleFile,
                project.plugins.hasPlugin('com.android.library'))
        def instrumentationScope = includeDependencies
                ? InstrumentationScope.ALL : InstrumentationScope.PROJECT
        variant.instrumentation.transformClassesWith(
                StringEncryptionVisitorFactory,
                instrumentationScope) { parameters ->
            parameters.registryKey.set(registryKey)
            parameters.fullCoverageInvocationNonce.set(
                    fullCoverageInvocationNonce(project, forceFullCoverage))
        }
        variant.instrumentation.setAsmFramesComputationMode(
                FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS)
        project.logger.lifecycle("[dex-cfg-obf] ${variantName}: string encryption enabled, " +
                "mode=${strings.resolvedMode()}, scope=${instrumentationScope}, " +
                "fullCoverage=${isFullStringCoverageInvocation(project, forceFullCoverage)}, " +
                "packages=${includes}, bridge=${bridgeClass}")
        return registryKey
    }

    /** Both properties retain the same producer Provider, preserving Gradle task dependency wiring. */
    static void wireStringProtectionRules(def variant, def ruleFile, boolean libraryVariant) {
        variant.proguardFiles.add(ruleFile)
        if (libraryVariant) variant.consumerProguardFiles.add(ruleFile)
    }

    static void validateStringQualityConfiguration(StringEncryptionExtension strings) {
        if (strings.minEncryptedStrings < 0) {
            throw new GradleException('[dex-cfg-obf] stringEncryption.minEncryptedStrings must be >= 0')
        }
        if (strings.minModifiedClasses < 0) {
            throw new GradleException('[dex-cfg-obf] stringEncryption.minModifiedClasses must be >= 0')
        }
        if (strings.maxSkippedStrings < 0) {
            throw new GradleException('[dex-cfg-obf] stringEncryption.maxSkippedStrings must be >= 0')
        }
        if (strings.maxUnsafeSkippedStrings < 0) {
            throw new GradleException('[dex-cfg-obf] stringEncryption.' +
                    'maxUnsafeSkippedStrings must be >= 0')
        }
        if (strings.maxFilteredStrings < 0) {
            throw new GradleException('[dex-cfg-obf] stringEncryption.maxFilteredStrings must be >= 0')
        }
    }

    /** The current final-DEX verifier scans the base APK inputs, not feature split APK DEX. */
    static void validateDynamicFeatureCoverage(Collection<?> dynamicFeatures,
                                               StringEncryptionExtension strings) {
        if (dynamicFeatures == null || dynamicFeatures.isEmpty()) return
        String message = '[dex-cfg-obf] dynamicFeatures are present but final-Dex string ' +
                'verification currently covers only the base APK inputs, not every feature split'
        if (strings.verifyFinalDex && strings.failOnPlaintextLeak) {
            throw new GradleException(message + '; strict whole-artifact coverage cannot be claimed')
        }
        // Non-strict mode is allowed, but configureStringEncryption warns and runtime reporting keeps
        // coverage non-FULL through hasDynamicFeatures(project).
    }

    static String combinedEvidenceSource(boolean anyCurrentEvidence,
                                         boolean anyRestoredEvidence,
                                         boolean missingEnabledEvidence) {
        if (missingEnabledEvidence) {
            return anyCurrentEvidence || anyRestoredEvidence ? 'PARTIAL_MISSING' : 'MISSING'
        }
        if (anyCurrentEvidence && anyRestoredEvidence) return 'MIXED'
        if (anyRestoredEvidence) return 'CACHED_VERIFIED'
        if (anyCurrentEvidence) return 'CURRENT_BUILD'
        return 'MISSING'
    }

    /** Resolve application-only dependency evidence paths once per variant, failing on ambiguity. */
    static List<String> validateDependencyEvidenceProjects(Project applicationProject,
                                                           Collection<?> configuredPaths) {
        if (applicationProject == null) {
            throw new GradleException('[dex-cfg-obf] application project is required')
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>()
        (configuredPaths ?: Collections.emptyList()).each { Object raw ->
            String path = raw == null ? '' : raw.toString().trim()
            if (path.isEmpty() || !path.startsWith(':') || path == ':') {
                throw new GradleException('[dex-cfg-obf] stringEncryption.' +
                        'dependencyEvidenceProjects entries must be absolute non-root project ' +
                        "paths such as ':feature': ${raw}")
            }
            Project dependencyProject = applicationProject.rootProject.findProject(path)
            if (dependencyProject == null) {
                throw new GradleException('[dex-cfg-obf] dependency evidence project does not ' +
                        "exist: ${path}")
            }
            if (dependencyProject.path == applicationProject.path) {
                throw new GradleException('[dex-cfg-obf] application cannot consume its own ' +
                        "string evidence: ${path}")
            }
            if (!normalized.add(dependencyProject.path)) {
                throw new GradleException('[dex-cfg-obf] duplicate dependency evidence project: ' +
                        dependencyProject.path)
            }
        }
        return Collections.unmodifiableList(new ArrayList<>(normalized))
    }

    private static void configureDependencyEvidenceTaskDependencies(
            Task task,
            Project applicationProject,
            Collection<String> dependencyProjects,
            String variantCap) {
        (dependencyProjects ?: Collections.emptyList()).each { String path ->
            task.dependsOn("${path}:compact${variantCap}LibraryStringConstantPools")
        }
    }

    /** A pre-minified library needs a second mapping composition, which is intentionally unsupported. */
    static void requireUnminifiedDependencyEvidenceTask(Task compactionTask,
                                                        String variantName,
                                                        String dependencyProjectPath) {
        def extra = compactionTask.extensions.extraProperties
        if (!extra.has(LIBRARY_EVIDENCE_MINIFIED_PROPERTY)) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} evidence task does not expose whether its variant " +
                    'was pre-minified')
        }
        Object raw = extra.get(LIBRARY_EVIDENCE_MINIFIED_PROPERTY)
        boolean minified = raw instanceof Boolean
                ? ((Boolean) raw).booleanValue()
                : Boolean.parseBoolean(String.valueOf(raw))
        if (minified) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} is pre-minified; original library member evidence " +
                    'cannot be mapped safely through the application R8 pass. Disable library ' +
                    'minification for this variant or omit it from dependencyEvidenceProjects')
        }
    }

    /** Immutable, already validated library evidence prepared for the final application DEX gate. */
    static final class DependencyStringEvidence {
        final String projectPath
        final StringEvidenceScope scope
        final ObfuscatorStats stats

        DependencyStringEvidence(String projectPath,
                                 StringEvidenceScope scope,
                                 ObfuscatorStats stats) {
            this.projectPath = projectPath
            this.scope = scope
            this.stats = stats
        }
    }

    /**
     * Validate a dependency's evidence against the exact current ASM transform outputs. This helper
     * deliberately accepts no transform digest from the application: the digest is private to the
     * library registry, while the output fingerprint, v3 scope and persisted internal digest pair
     * together prevent stale/cross-configuration evidence from being trusted.
     */
    static DependencyStringEvidence readDependencyStringEvidence(
            File evidenceFile,
            Collection<File> transformOutputs,
            String expectedStringTransformDigest,
            String variantName,
            String dependencyProjectPath) {
        return readDependencyStringEvidence(evidenceFile, transformOutputs,
                expectedStringTransformDigest, variantName, dependencyProjectPath, true,
                Integer.MAX_VALUE, Integer.MAX_VALUE)
    }

    static DependencyStringEvidence readDependencyStringEvidence(
            File evidenceFile,
            Collection<File> transformOutputs,
            String expectedStringTransformDigest,
            String variantName,
            String dependencyProjectPath,
            boolean requireFullCoverage) {
        return readDependencyStringEvidence(evidenceFile, transformOutputs,
                expectedStringTransformDigest, variantName, dependencyProjectPath,
                requireFullCoverage, Integer.MAX_VALUE, Integer.MAX_VALUE)
    }

    static DependencyStringEvidence readDependencyStringEvidence(
            File evidenceFile,
            Collection<File> transformOutputs,
            String expectedStringTransformDigest,
            String variantName,
            String dependencyProjectPath,
            boolean requireFullCoverage,
            int maxUnsafeSkippedStrings,
            int maxFilteredStrings) {
        if (transformOutputs == null || transformOutputs.isEmpty()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} has no ASM transform outputs to fingerprint")
        }
        String fingerprint
        try {
            fingerprint = StringClassConstantPoolCompactor.fingerprintOutputs(transformOutputs)
        } catch (Exception failure) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot fingerprint current " +
                    "library outputs for dependency ${dependencyProjectPath}", failure)
        }
        if (expectedStringTransformDigest == null
                || expectedStringTransformDigest.trim().isEmpty()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} did not expose its current string transform digest")
        }
        Optional<BuildEvidenceStore.StringEvidence> loaded
        try {
            loaded = BuildEvidenceStore.readString(evidenceFile, fingerprint,
                    expectedStringTransformDigest)
        } catch (Exception failure) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} string evidence is corrupt/unreadable", failure)
        }
        if (!loaded.isPresent()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} has no library string evidence; run clean with " +
                    '--rerun-tasks')
        }
        BuildEvidenceStore.StringEvidence evidence = loaded.get()
        requireStringOwnerScope(evidence, variantName,
                "dependency ${dependencyProjectPath} library")
        requireStringSkipReasonStats(evidence, maxUnsafeSkippedStrings,
                maxFilteredStrings, variantName,
                "dependency ${dependencyProjectPath} library")
        // readString(expected...) has already bound both current output fingerprint and digest.
        String dependencyCoverage = evidence.getCoverageStatus()
        boolean knownCoverage = isTrustedFullCoverage(dependencyCoverage)
                || 'PARTIAL_OR_FULL'.equals(dependencyCoverage)
                || 'CACHED_PARTIAL'.equals(dependencyCoverage)
        if (!knownCoverage || (requireFullCoverage
                && !isTrustedFullCoverage(dependencyCoverage))) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} evidence coverage is " +
                    "${dependencyCoverage}, expected " +
                    (requireFullCoverage ? 'FULL' : 'known current coverage'))
        }
        ObfuscatorStats stats = evidence.getStats()
        if (!stats.stringEncryptionEnabled) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} evidence does not record enabled string encryption")
        }
        if (!stats.stringPlaintextVerified || stats.stringPlaintextLeaks != 0) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} library plaintext gate is not a clean verified pass")
        }
        if (!fingerprint.equals(stats.artifactFingerprint)
                || !expectedStringTransformDigest.equals(stats.stringTransformDigest)) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: dependency " +
                    "${dependencyProjectPath} evidence metadata is not internally bound to the " +
                    'current artifact/configuration')
        }
        StringEvidenceScope scope = new StringEvidenceScope(
                evidence.getPlaintextSha256(),
                evidence.getPlaintextSha256ByOriginalClass(),
                evidence.getPlaintextSha256ByOriginalMethod(),
                evidence.getPlaintextSha256ByOriginalField())
        // Validate each dependency in isolation. Without this check, two malformed
        // evidence files could cross-fill each other's owner/member hash unions after merge.
        resolveFinalStringScope(scope.plaintextHashes,
                scope.plaintextHashesByOriginalClass,
                scope.plaintextHashesByOriginalMethod,
                scope.plaintextHashesByOriginalField,
                false, null, "${variantName} dependency ${dependencyProjectPath}")
        return new DependencyStringEvidence(dependencyProjectPath, scope, stats)
    }

    /** Load, validate and merge every configured library into the transient final-APK gate scope. */
    private static StringEvidenceScope mergeDependencyStringEvidence(
            Project applicationProject,
            Collection<String> dependencyProjects,
            String variantName,
            String variantCap,
            StringEvidenceScope applicationScope,
            ObfuscatorStats aggregateStats,
            boolean requireFullDependencyCoverage,
            int maxUnsafeSkippedStrings,
            int maxFilteredStrings) {
        TreeSet<String> hashes = new TreeSet<>(applicationScope.plaintextHashes)
        TreeMap<String, Set<String>> classes = mutableNestedStringMap(
                applicationScope.plaintextHashesByOriginalClass)
        TreeMap<String, Set<String>> methods = mutableNestedStringMap(
                applicationScope.plaintextHashesByOriginalMethod)
        TreeMap<String, Set<String>> fields = mutableNestedStringMap(
                applicationScope.plaintextHashesByOriginalField)
        String aggregateCoverage = aggregateStats.stringCoverageStatus
        String applicationMode = aggregateStats.stringEncryptionMode
        String applicationDigest = aggregateStats.stringTransformDigest
        boolean mixedMode = false
        TreeSet<String> dependencyDigestBindings = new TreeSet<>()
        (dependencyProjects ?: Collections.emptyList()).each { String path ->
            Project dependencyProject = applicationProject.rootProject.findProject(path)
            if (dependencyProject == null) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency evidence " +
                        "project disappeared after configuration: ${path}")
            }
            if (!dependencyProject.plugins.hasPlugin('com.android.library')
                    || !dependencyProject.plugins.hasPlugin('com.hunter.dexcfgobf')) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} must " +
                        'apply both com.android.library and com.hunter.dexcfgobf')
            }
            String compactionTaskName = "compact${variantCap}LibraryStringConstantPools"
            Task compactionTask = dependencyProject.tasks.findByName(compactionTaskName)
            if (compactionTask == null) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} did " +
                        "not register ${compactionTaskName}; enable its stringEncryption stage")
            }
            if (!compactionTask.state.executed || compactionTask.state.skipped
                    || compactionTask.state.failure != null) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} " +
                        "evidence task ${compactionTaskName} did not complete successfully")
            }
            requireUnminifiedDependencyEvidenceTask(compactionTask, variantName, path)
            def extra = compactionTask.extensions.extraProperties
            if (!extra.has(LIBRARY_EVIDENCE_DIGEST_PROPERTY)) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} " +
                        "evidence task ${compactionTaskName} did not expose its current transform digest")
            }
            String expectedDigest = extra.get(LIBRARY_EVIDENCE_DIGEST_PROPERTY)?.toString()
            String transformTaskName = "transform${variantCap}ClassesWithAsm"
            Set<Task> transforms = dependencyProject.tasks.matching {
                it.name == transformTaskName
            }.findAll()
            if (transforms.size() != 1) {
                throw new GradleException("[dex-cfg-obf] ${variantName}: dependency ${path} must " +
                        "have exactly one ${transformTaskName} task, found ${transforms.size()}")
            }
            LinkedHashSet<File> outputs = new LinkedHashSet<>(
                    transforms.first().outputs.files.files)
            File evidenceRoot = new File(dependencyProject.buildDir,
                    "intermediates/dex-cfg-obfuscator-evidence/${variantName}/library")
            File evidenceFile = BuildEvidenceStore.stringEvidenceFile(evidenceRoot,
                    variantName + '-library-class-pool')
            DependencyStringEvidence dependency = readDependencyStringEvidence(evidenceFile,
                    outputs, expectedDigest, variantName, path, requireFullDependencyCoverage,
                    maxUnsafeSkippedStrings, maxFilteredStrings)
            dependencyDigestBindings.add(path + '\u0000' +
                    dependency.stats.artifactFingerprint + '\u0000' +
                    dependency.stats.stringTransformDigest)
            hashes.addAll(dependency.scope.plaintextHashes)
            mergeNestedStringMap(classes,
                    dependency.scope.plaintextHashesByOriginalClass)
            mergeNestedStringMap(methods,
                    dependency.scope.plaintextHashesByOriginalMethod)
            mergeNestedStringMap(fields,
                    dependency.scope.plaintextHashesByOriginalField)
            aggregateStats.mergeFrom(dependency.stats)
            // Keep the weakest coverage. A FULL dependency must never upgrade a partial/unknown
            // application, while a permitted partial dependency must downgrade an application FULL.
            aggregateCoverage = weakestStringCoverage(aggregateCoverage,
                    dependency.stats.stringCoverageStatus)
            aggregateStats.stringCoverageStatus = aggregateCoverage
            if (applicationMode != null && !applicationMode.isEmpty()
                    && dependency.stats.stringEncryptionMode != null
                    && !applicationMode.equals(dependency.stats.stringEncryptionMode)) {
                mixedMode = true
            }
            aggregateStats.stringEncryptionMode = mixedMode ? 'MIXED' : applicationMode
            applicationProject.logger.lifecycle("[dex-cfg-obf] ${variantName}: merged " +
                    "${dependency.scope.plaintextHashes.size()} protected dependency value(s) " +
                    "from ${path} into the final DEX gate")
        }
        if (!dependencyDigestBindings.isEmpty()) {
            aggregateStats.stringTransformDigest = configurationDigest(
                    'aggregate-string-evidence-v1', applicationDigest,
                    dependencyDigestBindings)
        }
        return new StringEvidenceScope(hashes, classes, methods, fields)
    }

    /** Immutable protected-value evidence with its exact original owner scope. */
    static final class StringEvidenceScope {
        final Set<String> plaintextHashes
        final Map<String, Set<String>> plaintextHashesByOriginalClass
        final Map<String, Set<String>> plaintextHashesByOriginalMethod
        final Map<String, Set<String>> plaintextHashesByOriginalField

        StringEvidenceScope(Set<String> plaintextHashes,
                            Map<String, ? extends Set<String>> byOriginalClass,
                            Map<String, ? extends Set<String>> byOriginalMethod,
                            Map<String, ? extends Set<String>> byOriginalField) {
            this.plaintextHashes = Collections.unmodifiableSet(
                    new TreeSet<>(plaintextHashes ?: Collections.emptySet()))
            TreeMap<String, Set<String>> copied = new TreeMap<>()
            (byOriginalClass ?: Collections.emptyMap()).each {
                String owner, Set<String> hashes ->
                    copied.put(owner, Collections.unmodifiableSet(new TreeSet<>(hashes)))
            }
            this.plaintextHashesByOriginalClass = Collections.unmodifiableMap(copied)
            this.plaintextHashesByOriginalMethod = immutableNestedStringMap(byOriginalMethod)
            this.plaintextHashesByOriginalField = immutableNestedStringMap(byOriginalField)
        }
    }

    private static Map<String, Set<String>> immutableNestedStringMap(
            Map<String, ? extends Set<String>> source) {
        TreeMap<String, Set<String>> copied = new TreeMap<>()
        (source ?: Collections.emptyMap()).each { String key, Set<String> hashes ->
            copied.put(key, Collections.unmodifiableSet(new TreeSet<>(hashes)))
        }
        return Collections.unmodifiableMap(copied)
    }

    /** Immutable final DEX exact-site scope plus fail-closed global runtime fallback hashes. */
    static final class FinalStringScope {
        final Map<String, Set<String>> plaintextHashesByFinalClass
        final Map<String, Set<String>> plaintextHashesByFinalMethod
        final Map<String, Set<String>> plaintextHashesByFinalField
        final Set<String> globalRuntimeFallbackHashes
        final Set<String> removedOriginalSiteHashes
        final Set<String> identityFieldProvenanceTargets
        final int r8MappedMethodSites
        final int r8RemovedMethodSites
        final int r8IdentityMethodSites
        final int r8FallbackMethodSites
        final int r8MappedFieldProvenance
        final int r8RemovedFieldProvenance
        final int r8IdentityFieldProvenance
        final int r8FallbackFieldProvenance

        FinalStringScope(Map<String, ? extends Set<String>> byFinalClass,
                         Map<String, ? extends Set<String>> byFinalMethod,
                         Map<String, ? extends Set<String>> byFinalField,
                         Collection<String> globalRuntimeFallbackHashes,
                         Collection<String> removedOriginalSiteHashes = Collections.emptySet(),
                         Collection<String> identityFieldProvenanceTargets = Collections.emptySet(),
                         int r8MappedMethodSites = 0,
                         int r8RemovedMethodSites = 0,
                         int r8IdentityMethodSites = 0,
                         int r8FallbackMethodSites = 0,
                         int r8MappedFieldProvenance = 0,
                         int r8RemovedFieldProvenance = 0,
                         int r8IdentityFieldProvenance = 0,
                         int r8FallbackFieldProvenance = 0) {
            plaintextHashesByFinalClass = immutableNestedStringMap(byFinalClass)
            plaintextHashesByFinalMethod = immutableNestedStringMap(byFinalMethod)
            plaintextHashesByFinalField = immutableNestedStringMap(byFinalField)
            this.globalRuntimeFallbackHashes = Collections.unmodifiableSet(
                    new TreeSet<>(globalRuntimeFallbackHashes ?: Collections.emptySet()))
            this.removedOriginalSiteHashes = Collections.unmodifiableSet(
                    new TreeSet<>(removedOriginalSiteHashes ?: Collections.emptySet()))
            this.identityFieldProvenanceTargets = Collections.unmodifiableSet(
                    new TreeSet<>(identityFieldProvenanceTargets ?: Collections.emptySet()))
            this.r8MappedMethodSites = r8MappedMethodSites
            this.r8RemovedMethodSites = r8RemovedMethodSites
            this.r8IdentityMethodSites = r8IdentityMethodSites
            this.r8FallbackMethodSites = r8FallbackMethodSites
            this.r8MappedFieldProvenance = r8MappedFieldProvenance
            this.r8RemovedFieldProvenance = r8RemovedFieldProvenance
            this.r8IdentityFieldProvenance = r8IdentityFieldProvenance
            this.r8FallbackFieldProvenance = r8FallbackFieldProvenance
        }

        Map<String, Set<String>> getPlaintextHashesByFinalClass() {
            return plaintextHashesByFinalClass
        }

        Map<String, Set<String>> getPlaintextHashesByFinalMethod() {
            return plaintextHashesByFinalMethod
        }

        Map<String, Set<String>> getPlaintextHashesByFinalField() {
            return plaintextHashesByFinalField
        }

        Set<String> getGlobalRuntimeFallbackHashes() {
            return globalRuntimeFallbackHashes
        }

        Set<String> getRemovedOriginalSiteHashes() {
            return removedOriginalSiteHashes
        }

        Set<String> getIdentityFieldProvenanceTargets() {
            return identityFieldProvenanceTargets
        }
    }

    /**
     * An AGP ASM transform may visit only changed classes. Keep both the prior protected hashes and
     * their original owners so an unchanged class cannot lose its exact final-DEX gate scope.
     */
    private static StringEvidenceScope mergePriorStringEvidence(
            Project project,
            File evidenceFile,
            String stringDigest,
            Set<String> currentHashes,
            Set<String> currentVisitedOriginalClasses,
            Set<String> currentActiveOriginalClasses,
            Map<String, ? extends Set<String>> currentHashesByOriginalClass,
            Map<String, ? extends Set<String>> currentHashesByOriginalMethod,
            Map<String, ? extends Set<String>> currentHashesByOriginalField,
            int maxUnsafeSkippedStrings,
            int maxFilteredStrings,
            String variantName,
            String artifactLabel) {
        return mergePriorStringEvidence(project, evidenceFile, stringDigest, currentHashes,
                currentVisitedOriginalClasses, currentActiveOriginalClasses,
                currentHashesByOriginalClass, currentHashesByOriginalMethod,
                currentHashesByOriginalField, maxUnsafeSkippedStrings, maxFilteredStrings,
                variantName, artifactLabel, isFullStringCoverageBuild(project))
    }

    private static StringEvidenceScope mergePriorStringEvidence(
            Project project,
            File evidenceFile,
            String stringDigest,
            Set<String> currentHashes,
            Set<String> currentVisitedOriginalClasses,
            Set<String> currentActiveOriginalClasses,
            Map<String, ? extends Set<String>> currentHashesByOriginalClass,
            Map<String, ? extends Set<String>> currentHashesByOriginalMethod,
            Map<String, ? extends Set<String>> currentHashesByOriginalField,
            int maxUnsafeSkippedStrings,
            int maxFilteredStrings,
            String variantName,
            String artifactLabel,
            boolean fullCurrentCoverage) {
        TreeSet<String> mergedHashes = new TreeSet<>(currentHashes ?: Collections.emptySet())
        TreeMap<String, Set<String>> mergedOwners = new TreeMap<>()
        (currentHashesByOriginalClass ?: Collections.emptyMap()).each {
            String owner, Set<String> hashes ->
                mergedOwners.put(owner, new TreeSet<>(hashes))
        }
        TreeMap<String, Set<String>> mergedMethods = mutableNestedStringMap(
                currentHashesByOriginalMethod)
        TreeMap<String, Set<String>> mergedFields = mutableNestedStringMap(
                currentHashesByOriginalField)
        TreeSet<String> currentOwnerHashes = nestedStringValues(mergedOwners)
        if (!mergedHashes.equals(currentOwnerHashes)) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: current incremental " +
                    "${artifactLabel} string evidence is not exactly owner-scoped; values and " +
                    'hashes are not logged; run clean with --rerun-tasks')
        }
        if (fullCurrentCoverage) {
            return new StringEvidenceScope(mergedHashes, mergedOwners,
                    mergedMethods, mergedFields)
        }
        Optional<BuildEvidenceStore.StringEvidence> prior
        try {
            prior = BuildEvidenceStore.readString(evidenceFile)
        } catch (Exception evidenceFailure) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: prior ${artifactLabel} " +
                    "string evidence is corrupt/unreadable; run clean with --rerun-tasks",
                    evidenceFailure)
        }
        if (!prior.isPresent()) return new StringEvidenceScope(mergedHashes, mergedOwners,
                mergedMethods, mergedFields)
        if (!stringDigest.equals(prior.get().getStringTransformDigest())) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: ${artifactLabel} string " +
                    "configuration changed while prior incremental evidence exists; run clean " +
                    "with --rerun-tasks so every class is re-instrumented")
        }
        requireStringOwnerScope(prior.get(), variantName, artifactLabel)
        requireStringSkipReasonStats(prior.get(), maxUnsafeSkippedStrings,
                maxFilteredStrings, variantName, artifactLabel)
        TreeSet<String> priorOwnerHashes = nestedStringValues(
                prior.get().getPlaintextSha256ByOriginalClass())
        if (!new TreeSet<>(prior.get().getPlaintextSha256()).equals(priorOwnerHashes)) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: prior ${artifactLabel} " +
                    'string evidence is not exactly owner-scoped; values and hashes are not ' +
                    'logged; run clean with --rerun-tasks')
        }
        TreeSet<String> visitedOwners = new TreeSet<>()
        (currentVisitedOriginalClasses ?: Collections.emptySet()).each { String owner ->
            String normalized = ObfuscatorConfig.normalizeClassName(owner)
            if (!normalized.isEmpty()) visitedOwners.add(normalized)
        }
        TreeSet<String> activeOwners = new TreeSet<>()
        (currentActiveOriginalClasses ?: Collections.emptySet()).each { String owner ->
            String normalized = ObfuscatorConfig.normalizeClassName(owner)
            if (!normalized.isEmpty()) activeOwners.add(normalized)
        }
        int beforeHashes = mergedHashes.size()
        int beforeOwners = mergedOwners.size()

        prior.get().getPlaintextSha256ByOriginalClass().each {
            String owner, Set<String> hashes ->
                String normalized = ObfuscatorConfig.normalizeClassName(owner)
                if (activeOwners.contains(normalized) && !visitedOwners.contains(normalized)) {
                    mergedOwners.computeIfAbsent(owner, ignored -> new TreeSet<>()).addAll(hashes)
                }
        }
        mergeUnvisitedOriginalMemberScope(mergedMethods,
                prior.get().getPlaintextSha256ByOriginalMethod(), visitedOwners, activeOwners)
        mergeUnvisitedOriginalMemberScope(mergedFields,
                prior.get().getPlaintextSha256ByOriginalField(), visitedOwners, activeOwners)

        mergedHashes.clear()
        mergedOwners.values().each { Set<String> hashes -> mergedHashes.addAll(hashes) }
        int restoredHashes = mergedHashes.size() - beforeHashes
        int restoredOwners = mergedOwners.size() - beforeOwners
        if (restoredHashes > 0 || restoredOwners > 0) {
            project.logger.lifecycle("[dex-cfg-obf] ${variantName}: carried " +
                    "${restoredHashes} prior protected-value hash(es) and " +
                    "${restoredOwners} original owner(s) into the ${artifactLabel} gate")
        }
        return new StringEvidenceScope(mergedHashes, mergedOwners, mergedMethods, mergedFields)
    }

    private static TreeSet<String> nestedStringValues(
            Map<String, ? extends Set<String>> source) {
        TreeSet<String> values = new TreeSet<>()
        (source ?: Collections.emptyMap()).values().each {
            Set<String> hashes -> values.addAll(hashes)
        }
        return values
    }

    private static void mergeUnvisitedOriginalMemberScope(
            Map<String, Set<String>> destination,
            Map<String, Set<String>> source,
            Set<String> visitedOwners,
            Set<String> activeOwners) {
        (source ?: Collections.emptyMap()).each { String member, Set<String> hashes ->
            String owner = ObfuscatorConfig.normalizeClassName(originalMemberOwner(member))
            if (activeOwners.contains(owner) && !visitedOwners.contains(owner)) {
                destination.computeIfAbsent(member, ignored -> new TreeSet<>()).addAll(hashes)
            }
        }
    }

    private static TreeMap<String, Set<String>> mutableNestedStringMap(
            Map<String, ? extends Set<String>> source) {
        TreeMap<String, Set<String>> result = new TreeMap<>()
        (source ?: Collections.emptyMap()).each { String key, Set<String> hashes ->
            result.put(key, new TreeSet<>(hashes))
        }
        return result
    }

    private static void mergeNestedStringMap(Map<String, Set<String>> destination,
                                             Map<String, Set<String>> source) {
        (source ?: Collections.emptyMap()).each { String key, Set<String> hashes ->
            destination.computeIfAbsent(key, ignored -> new TreeSet<>()).addAll(hashes)
        }
    }

    private static void requireStringOwnerScope(BuildEvidenceStore.StringEvidence evidence,
                                                String variantName,
                                                String artifactLabel) {
        if (!evidence.hasOwnerScope() || !evidence.hasMemberScope()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: prior ${artifactLabel} " +
                    "string evidence predates exact owner scoping; run clean with --rerun-tasks")
        }
    }

    static void requireStringSkipReasonStats(BuildEvidenceStore.StringEvidence evidence,
                                             int maxUnsafeSkippedStrings,
                                             int maxFilteredStrings,
                                             String variantName,
                                             String artifactLabel) {
        boolean finiteSkipBudget = maxUnsafeSkippedStrings != Integer.MAX_VALUE
                || maxFilteredStrings != Integer.MAX_VALUE
        if (finiteSkipBudget && !evidence.hasSkipReasonStats()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: prior ${artifactLabel} " +
                    "string evidence format v${evidence.getFormatVersion()} predates skip-reason " +
                    'statistics required by maxUnsafeSkippedStrings/maxFilteredStrings; run clean ' +
                    'with --rerun-tasks')
        }
    }

    /**
     * Resolve the evidence to final DEX sites. Runtime instructions are gated by their exact
     * mapped method (descriptors are retained for non-R8 builds and become owner+name after R8
     * because ordinary mapping files cannot reliably expose residual prototypes). Static-final
     * field ConstantValues are executable in owner {@code <clinit>()V}; the field map is retained
     * as provenance only and never becomes a final field target. Therefore removal or remapping of
     * the field itself is not proof that the generated decrypt instruction disappeared. A normal
     * field mapping identifies the final owner whose {@code <clinit>} must be scanned; only a
     * removed {@code <clinit>} relation or whole-owner removal proves the payload disappeared.
     *
     * <p>R8 may omit a member relation because it was removed or because a keep rule retained its
     * identity. Exact usage.txt removal is accepted only when the companion exists; exact seeds.txt
     * identity becomes an owner/name/descriptor candidate that the final DEX verifier must observe.
     * Missing/malformed companion evidence stays on the fail-closed global runtime-payload gate.
     * R8's {@code R8$$REMOVED$$CLASS$$n} pseudo owners are affirmative removal evidence for a
     * whole owner or executable method relation, but not for field provenance alone.</p>
     */
    static FinalStringScope resolveFinalStringScope(
            Set<String> plaintextHashes,
            Map<String, ? extends Set<String>> originalClassHashes,
            Map<String, ? extends Set<String>> originalMethodHashes,
            Map<String, ? extends Set<String>> originalFieldHashes,
            boolean useR8Mapping,
            File r8MappingFile,
            String variantName) {
        Set<String> expected = new TreeSet<>(plaintextHashes ?: Collections.emptySet())
        TreeMap<String, Set<String>> classes = canonicalOriginalClassScope(
                originalClassHashes, expected, variantName)
        TreeMap<String, Set<String>> methods = canonicalOriginalMemberScope(
                originalMethodHashes, expected, true, variantName)
        TreeMap<String, Set<String>> fields = canonicalOriginalMemberScope(
                originalFieldHashes, expected, false, variantName)
        validateOriginalStringScope(expected, classes, methods, fields, variantName)

        TreeMap<String, Set<String>> finalClasses = new TreeMap<>()
        TreeMap<String, Set<String>> finalMethods = new TreeMap<>()
        TreeMap<String, Set<String>> finalFields = new TreeMap<>()
        TreeSet<String> globalRuntimeFallback = new TreeSet<>()
        if (!useR8Mapping) {
            classes.each { String owner, Set<String> hashes ->
                addStringScopeHashes(finalClasses, owner, hashes)
            }
            methods.each { String method, Set<String> hashes ->
                addStringScopeHashes(finalMethods, method, hashes)
            }
            return new FinalStringScope(finalClasses, finalMethods, finalFields,
                    globalRuntimeFallback)
        }

        if (r8MappingFile == null || !r8MappingFile.isFile()) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: R8 mapping.txt is required " +
                    "for exact string site scoping")
        }
        R8MappingResolver.ExactOwnerResolution ownerResolution
        R8MappingResolver.ExactMemberResolution memberResolution
        R8MappingResolver.ShrinkerCompanionReports companionReports
        try {
            ownerResolution = R8MappingResolver.resolveExactOwners(
                    r8MappingFile, classes.keySet())
            memberResolution = R8MappingResolver.resolveExactMembers(
                    r8MappingFile, methods.keySet(), fields.keySet())
            companionReports = R8MappingResolver.readCompanionReports(
                    r8MappingFile, methods.keySet(), fields.keySet())
        } catch (Exception mappingFailure) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: cannot resolve exact string " +
                    "sites through R8 mapping", mappingFailure)
        }

        TreeMap<String, Set<String>> fieldHashesByOwner = new TreeMap<>()
        fields.each { String originalField, Set<String> hashes ->
            addStringScopeHashes(fieldHashesByOwner,
                    originalMemberOwner(originalField), hashes)
        }
        TreeMap<String, Set<String>> coveredByOriginalOwner = new TreeMap<>()
        TreeSet<String> removedOriginalSiteHashes = new TreeSet<>()
        TreeSet<String> identityFieldProvenanceTargets = new TreeSet<>()
        int mappedMethodSites = 0
        int removedMethodSites = 0
        int identityMethodSites = 0
        int fallbackMethodSites = 0
        int mappedFieldProvenance = 0
        int removedFieldProvenance = 0
        int identityFieldProvenance = 0
        int fallbackFieldProvenance = 0

        // Field-derived hashes are classified from field provenance below, but field removal alone
        // never proves that R8 eliminated the generated decrypt call in <clinit>.
        methods.each { String originalMethod, Set<String> allMethodHashes ->
            TreeSet<String> hashes = new TreeSet<>(allMethodHashes)
            String originalOwner = originalMemberOwner(originalMethod)
            boolean classInitializer = originalMethod.endsWith('-><clinit>()V')
            if (classInitializer) {
                hashes.removeAll(fieldHashesByOwner.get(originalOwner)
                        ?: Collections.emptySet())
            }
            if (hashes.isEmpty()) return
            addStringScopeHashes(coveredByOriginalOwner, originalOwner, hashes)

            if (memberResolution.getConflictingMethods().containsKey(originalMethod)) {
                globalRuntimeFallback.addAll(hashes)
                fallbackMethodSites++
                return
            }
            Set<R8MappingResolver.FinalMember> targets =
                    memberResolution.getResolvedMethods().get(originalMethod)
            List<R8MappingResolver.FinalMember> usableTargets = (targets
                    ?: Collections.emptySet()).findAll {
                !isR8RemovedClassOwner(it.getOwnerInternalName())
            }.toList()
            if (!usableTargets.isEmpty()) {
                usableTargets.each { R8MappingResolver.FinalMember finalMethod ->
                    String finalOwner = finalMethod.getOwnerInternalName()
                    String finalKey = finalOwner + '->' + finalMethod.getMemberName()
                    if (classInitializer) finalKey += '()V'
                    addStringScopeHashes(finalMethods, finalKey, hashes)
                    addStringScopeHashes(finalClasses, finalOwner, hashes)
                }
                mappedMethodSites++
                return
            }
            if (targets != null && !targets.isEmpty()) {
                // R8's synthetic removed owner is affirmative elimination evidence.
                removedOriginalSiteHashes.addAll(hashes)
                removedMethodSites++
                return
            }
            String mappedOwner = ownerResolution.getResolvedOwners().get(originalOwner)
            if (isR8RemovedClassOwner(mappedOwner)
                    || companionReports.isMethodRemoved(originalMethod)) {
                removedOriginalSiteHashes.addAll(hashes)
                removedMethodSites++
                return
            }
            if (companionReports.isMethodSeeded(originalMethod)) {
                String identityOwner = mappedOwner ?: originalOwner
                String memberAndDescriptor = originalMethod.substring(
                        originalMethod.indexOf('->') + 2)
                addStringScopeHashes(finalMethods,
                        identityOwner + '->' + memberAndDescriptor, hashes)
                addStringScopeHashes(finalClasses, identityOwner, hashes)
                identityMethodSites++
                return
            }
            globalRuntimeFallback.addAll(hashes)
            fallbackMethodSites++
        }

        fields.each { String originalField, Set<String> hashes ->
            String originalOwner = originalMemberOwner(originalField)
            addStringScopeHashes(coveredByOriginalOwner, originalOwner, hashes)
            String originalClinit = originalOwner + '-><clinit>()V'
            Set<R8MappingResolver.FinalMember> clinitTargets =
                    memberResolution.getResolvedMethods().get(originalClinit)
            List<R8MappingResolver.FinalMember> usableClinitTargets = (clinitTargets
                    ?: Collections.emptySet()).findAll {
                !isR8RemovedClassOwner(it.getOwnerInternalName())
            }.toList()
            Set<R8MappingResolver.FinalMember> fieldTargets =
                    memberResolution.getResolvedFields().get(originalField)
            List<String> mappedInitializerOwners = usableClinitTargets.collect {
                it.getOwnerInternalName()
            }
            if (!mappedInitializerOwners.isEmpty()) {
                mappedInitializerOwners.toSet().each { String finalOwner ->
                    addStringScopeHashes(finalMethods,
                            finalOwner + '-><clinit>()V', hashes)
                    addStringScopeHashes(finalClasses, finalOwner, hashes)
                }
                mappedFieldProvenance++
                return
            }
            if (clinitTargets != null && !clinitTargets.isEmpty()) {
                // Only a pseudo target for the executable initializer itself is removal proof.
                removedOriginalSiteHashes.addAll(hashes)
                removedFieldProvenance++
                return
            }
            if (memberResolution.getConflictingMethods().containsKey(originalClinit)) {
                globalRuntimeFallback.addAll(hashes)
                fallbackFieldProvenance++
                return
            }
            String mappedOwner = ownerResolution.getResolvedOwners().get(originalOwner)
            if (isR8RemovedClassOwner(mappedOwner)
                    || companionReports.isClassRemoved(originalOwner)
                    || companionReports.isMethodRemoved(originalClinit)) {
                removedOriginalSiteHashes.addAll(hashes)
                removedFieldProvenance++
                return
            }
            List<String> usableFieldOwners = (fieldTargets
                    ?: Collections.emptySet()).findAll {
                !isR8RemovedClassOwner(it.getOwnerInternalName())
            }.collect { it.getOwnerInternalName() }.toSet().toList()
            if (!usableFieldOwners.isEmpty()) {
                // R8 can omit the unrenamed <clinit> relation while still providing the exact
                // residual field relation. The field's final owner is then the narrowest sound
                // executable target: the generated decrypt payload executes in that owner's
                // <clinit>, regardless of whether the field itself was renamed.
                usableFieldOwners.each { String finalOwner ->
                    addStringScopeHashes(finalMethods,
                            finalOwner + '-><clinit>()V', hashes)
                    addStringScopeHashes(finalClasses, finalOwner, hashes)
                }
                mappedFieldProvenance++
                return
            }
            if ((fieldTargets != null && !fieldTargets.isEmpty())
                    || memberResolution.getConflictingFields().containsKey(originalField)
                    || companionReports.isFieldRemoved(originalField)) {
                // A field can be removed/renamed while its generated decrypt payload is moved or
                // retained in <clinit>. Without an executable initializer relation, fail closed.
                globalRuntimeFallback.addAll(hashes)
                fallbackFieldProvenance++
                return
            }
            Set<String> seededDescriptors =
                    companionReports.getSeededFieldDescriptors(originalField)
            if (seededDescriptors.contains('Ljava/lang/String;')) {
                String identityOwner = mappedOwner ?: originalOwner
                String fieldName = originalField.substring(originalField.indexOf('->') + 2)
                identityFieldProvenanceTargets.add(
                        identityOwner + '->' + fieldName + ':Ljava/lang/String;')
                addStringScopeHashes(finalMethods,
                        identityOwner + '-><clinit>()V', hashes)
                addStringScopeHashes(finalClasses, identityOwner, hashes)
                identityFieldProvenance++
                return
            }
            globalRuntimeFallback.addAll(hashes)
            fallbackFieldProvenance++
        }

        boolean complete = true
        classes.each { String owner, Set<String> hashes ->
            if (!hashes.equals(coveredByOriginalOwner.get(owner))) complete = false
        }
        TreeSet<String> classifiedHashes = new TreeSet<>(globalRuntimeFallback)
        finalMethods.values().each { Set<String> hashes -> classifiedHashes.addAll(hashes) }
        classifiedHashes.addAll(removedOriginalSiteHashes)
        if (!complete || !expected.equals(classifiedHashes)) {
            throw new GradleException("[dex-cfg-obf] ${variantName}: R8 mapping lost part of the " +
                    "exact string site scope; run clean with --rerun-tasks")
        }
        TreeSet<String> removedOnlyHashes = new TreeSet<>(removedOriginalSiteHashes)
        removedOnlyHashes.removeAll(globalRuntimeFallback)
        finalMethods.values().each { Set<String> hashes -> removedOnlyHashes.removeAll(hashes) }
        return new FinalStringScope(finalClasses, finalMethods, finalFields,
                globalRuntimeFallback, removedOnlyHashes, identityFieldProvenanceTargets,
                mappedMethodSites, removedMethodSites, identityMethodSites,
                fallbackMethodSites, mappedFieldProvenance, removedFieldProvenance,
                identityFieldProvenance, fallbackFieldProvenance)
    }

    private static TreeMap<String, Set<String>> canonicalOriginalClassScope(
            Map<String, ? extends Set<String>> source,
            Set<String> expected,
            String variantName) {
        TreeMap<String, Set<String>> result = new TreeMap<>()
        (source ?: Collections.emptyMap()).each { String owner, Set<String> hashes ->
            String normalized = ObfuscatorConfig.normalizeClassName(owner)
            if (!validInternalOwner(normalized)) {
                throw invalidStringScope(variantName)
            }
            addValidatedStringScopeHashes(result, normalized, hashes, expected, variantName)
        }
        return result
    }

    private static TreeMap<String, Set<String>> canonicalOriginalMemberScope(
            Map<String, ? extends Set<String>> source,
            Set<String> expected,
            boolean method,
            String variantName) {
        TreeMap<String, Set<String>> result = new TreeMap<>()
        (source ?: Collections.emptyMap()).each { String memberKey, Set<String> hashes ->
            int arrow = memberKey == null ? -1 : memberKey.indexOf('->')
            if (arrow <= 0 || memberKey.indexOf('->', arrow + 2) >= 0) {
                throw invalidStringScope(variantName)
            }
            String owner = ObfuscatorConfig.normalizeClassName(memberKey.substring(0, arrow))
            String member = memberKey.substring(arrow + 2)
            boolean validMember = !member.isEmpty() && member.indexOf('#') < 0
            if (method) {
                int open = member.indexOf('(')
                int close = member.indexOf(')', open + 1)
                validMember = validMember && open > 0 && close > open &&
                        close < member.length() - 1 && member.indexOf('(', open + 1) < 0 &&
                        member.indexOf(')', close + 1) < 0
            } else {
                validMember = validMember && member.indexOf('(') < 0 && member.indexOf(')') < 0
            }
            if (!validInternalOwner(owner) || !validMember) {
                throw invalidStringScope(variantName)
            }
            addValidatedStringScopeHashes(result, owner + '->' + member, hashes,
                    expected, variantName)
        }
        return result
    }

    private static void validateOriginalStringScope(
            Set<String> expected,
            Map<String, Set<String>> classes,
            Map<String, Set<String>> methods,
            Map<String, Set<String>> fields,
            String variantName) {
        if (expected.isEmpty()) {
            if (!classes.isEmpty() || !methods.isEmpty() || !fields.isEmpty()) {
                throw invalidStringScope(variantName)
            }
            return
        }
        if (classes.isEmpty() || methods.isEmpty()) {
            throw invalidStringScope(variantName)
        }
        TreeSet<String> classUnion = new TreeSet<>()
        classes.values().each { classUnion.addAll(it) }
        TreeMap<String, Set<String>> methodHashesByOwner = new TreeMap<>()
        methods.each { String method, Set<String> hashes ->
            String owner = originalMemberOwner(method)
            Set<String> ownerHashes = classes.get(owner)
            if (ownerHashes == null || !ownerHashes.containsAll(hashes)) {
                throw invalidStringScope(variantName)
            }
            addStringScopeHashes(methodHashesByOwner, owner, hashes)
        }
        // Field relations are provenance only. Every field hash must already be represented at
        // its executable <clinit>()V method site, which is enforced by the per-owner equality.
        fields.each { String field, Set<String> hashes ->
            String owner = originalMemberOwner(field)
            Set<String> ownerHashes = classes.get(owner)
            Set<String> classInitializerHashes = methods.get(owner + '-><clinit>()V')
            if (ownerHashes == null || !ownerHashes.containsAll(hashes)
                    || classInitializerHashes == null
                    || !classInitializerHashes.containsAll(hashes)) {
                throw invalidStringScope(variantName)
            }
        }
        boolean exact = expected.equals(classUnion)
        classes.each { String owner, Set<String> hashes ->
            if (!hashes.equals(methodHashesByOwner.get(owner))) exact = false
        }
        if (!exact) throw invalidStringScope(variantName)
    }

    private static void addValidatedStringScopeHashes(
            Map<String, Set<String>> target,
            String key,
            Set<String> hashes,
            Set<String> expected,
            String variantName) {
        if (hashes == null || hashes.isEmpty() || !expected.containsAll(hashes)) {
            throw invalidStringScope(variantName)
        }
        addStringScopeHashes(target, key, hashes)
    }

    private static void addStringScopeHashes(Map<String, Set<String>> target,
                                             String key,
                                             Collection<String> hashes) {
        target.computeIfAbsent(key, ignored -> new TreeSet<>()).addAll(hashes)
    }

    private static String originalMemberOwner(String memberKey) {
        int arrow = memberKey.indexOf('->')
        return arrow <= 0 ? '' : memberKey.substring(0, arrow)
    }

    private static boolean validInternalOwner(String owner) {
        if (owner == null || owner.isEmpty() || owner.startsWith('/') || owner.endsWith('/') ||
                owner.contains('//') || owner.indexOf(';') >= 0 || owner.indexOf('[') >= 0) {
            return false
        }
        for (int i = 0; i < owner.length(); i++) {
            char c = owner.charAt(i)
            if (Character.isWhitespace(c) || Character.isISOControl(c)) return false
        }
        return true
    }

    private static boolean isR8RemovedClassOwner(String owner) {
        return owner != null && owner.matches(
                'R8\\$\\$REMOVED\\$\\$CLASS\\$\\$[0-9]+')
    }

    private static GradleException invalidStringScope(String variantName) {
        return new GradleException("[dex-cfg-obf] ${variantName}: exact string site scope is " +
                "empty, incomplete, or invalid; run clean with --rerun-tasks")
    }

    private static boolean hasDynamicFeatures(Project project) {
        try {
            def android = project.extensions.findByName('android')
            return android != null && !(android.dynamicFeatures ?: []).isEmpty()
        } catch (groovy.lang.MissingPropertyException ignored) {
            return false
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

    /** 将 Gradle DSL 的 CFG 质量门禁复制到核心配置，并尽早拒绝无效阈值。 */
    static void applyQualityBudgets(DexObfuscatorExtension cfg, ObfuscatorConfig config) {
        if (cfg.minObfuscatedMethods < 0) {
            throw new GradleException(
                    '[dex-cfg-obf] dexObfuscator.minObfuscatedMethods must be >= 0')
        }
        if (cfg.minFlattenedMethods < 0) {
            throw new GradleException(
                    '[dex-cfg-obf] dexObfuscator.minFlattenedMethods must be >= 0')
        }
        if (!Double.isFinite(cfg.minObfuscatedRatio)
                || cfg.minObfuscatedRatio < 0.0d || cfg.minObfuscatedRatio > 1.0d) {
            throw new GradleException('[dex-cfg-obf] dexObfuscator.minObfuscatedRatio ' +
                    'must be finite and in [0, 1]')
        }
        if (!Double.isFinite(cfg.maxSizeIncreasePercent)
                || cfg.maxSizeIncreasePercent < 0.0d) {
            throw new GradleException('[dex-cfg-obf] dexObfuscator.maxSizeIncreasePercent ' +
                    'must be finite and >= 0')
        }
        config.minObfuscatedMethods = cfg.minObfuscatedMethods
        config.minFlattenedMethods = cfg.minFlattenedMethods
        config.minObfuscatedRatio = cfg.minObfuscatedRatio
        config.maxSizeIncreasePercent = cfg.maxSizeIncreasePercent
    }

    /** 0.0.15 binary/source compatibility for callers of the old helper signature. */
    @Deprecated
    static void applyQualityBudgets(DexCfgObfuscatorExtension ext, ObfuscatorConfig config) {
        applyQualityBudgets(ext.dexObfuscator, config)
    }

    private static String configurationDigest(Object... values) {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance('SHA-256')
        values.each { Object value ->
            byte[] bytes = String.valueOf(value).getBytes(java.nio.charset.StandardCharsets.UTF_8)
            digest.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array())
            digest.update(bytes)
        }
        StringBuilder hex = new StringBuilder(64)
        digest.digest().each { byte value -> hex.append(String.format('%02x', value & 0xff)) }
        return hex.toString()
    }

    /** 只包含会改变 CFG 产物的配置；质量阈值变化复用同一统计并重新执行门禁。 */
    private static String cfgTransformDigest(ObfuscatorConfig config) {
        return configurationDigest('cfg-transform-v4-stacktrace-lines-marker-v1',
                config.depth, config.maxRegisters, config.maxInstructions, config.seed,
                config.skipMethodsWithTryCatch, config.stripDebugInfo, config.verifyStructure,
                config.enableRegisterTypeSeparation, config.enablePayloadRelocation,
                config.enableMultiTemplate,
                new TreeSet<>(config.includePrefixes), new TreeSet<>(config.excludePrefixes),
                config.requireResolvedIncludeClasses,
                new TreeSet<>(config.resolvedIncludeClasses),
                new TreeSet<>(config.resolvedClassWideIncludeClasses),
                new TreeSet<>(config.resolvedIncludeMethods),
                new TreeSet<>(config.requiredResolvedIncludeMethods))
    }

    /** 将实际扫描的全部 DEX 内容绑定成一个稳定摘要，不记录业务字符串。 */
    private static String fingerprintDexDirectories(List<File> dexDirs) {
        if (dexDirs == null || dexDirs.isEmpty()) {
            throw new IllegalArgumentException('DEX audit directory list must not be empty')
        }
        List<String> entries = dexDirs.collect { File dir ->
            dir.canonicalPath + '=' + DexDirectoryState.fingerprint(dir)
        }.sort()
        return configurationDigest('dex-audit-v1', entries)
    }

    /** 避免 app/library 共用 namespace 时生成同名 bridge 导致最终 DEX duplicate class。 */
    static String defaultBridgeClass(String namespace, String projectPath) {
        String digest = configurationDigest(projectPath ?: ':')
        return namespace + '.DexStringDecryptor_' + digest.substring(0, 8)
    }

    /** Exact, case-insensitive variant/build-type filtering; an empty filter enables every variant. */
    static boolean isCfgEnabledForVariant(boolean enabled,
                                          Collection<?> enabledVariants,
                                          String variantName,
                                          String buildType) {
        boolean selected = isVariantSelected(enabledVariants, variantName, buildType,
                'enabledVariants')
        return enabled && selected
    }

    /**
     * String protection uses two alternative enablement inputs. The global flag enables every
     * variant, while a non-empty selector enables only matching variants. An empty selector must
     * not turn the default false flag into an implicit global enablement.
     */
    static boolean isStringEnabledForVariant(boolean enabled,
                                             Collection<?> enabledVariants,
                                             String variantName,
                                             String buildType) {
        Collection<?> selectors = enabledVariants ?: Collections.emptyList()
        boolean selected = !selectors.isEmpty() &&
                isVariantSelected(selectors, variantName, buildType,
                        'stringEncryption.enabledVariants')
        return enabled || selected
    }

    /** Shared exact, case-insensitive selector for independent variant-aware stages/gates. */
    static boolean isVariantSelected(Collection<?> configuredVariants,
                                     String variantName,
                                     String buildType,
                                     String propertyName) {
        List<String> filters = []
        (configuredVariants ?: Collections.emptyList()).each { Object raw ->
            if (raw == null || raw.toString().trim().isEmpty()) {
                throw new GradleException("[dex-cfg-obf] ${propertyName} entries must not be blank")
            }
            filters.add(raw.toString().trim())
        }
        if (filters.isEmpty()) return true
        String normalizedVariant = variantName == null ? '' : variantName.trim()
        String normalizedBuildType = buildType == null ? '' : buildType.trim()
        return filters.any { String filter ->
            filter.equalsIgnoreCase(normalizedVariant) ||
                    (!normalizedBuildType.isEmpty()
                            && filter.equalsIgnoreCase(normalizedBuildType))
        }
    }

    private static void warnIfDecryptorMissesCfg(Project project,
                                                 DexObfuscatorExtension cfg,
                                                 StringEncryptionExtension strings,
                                                 String className,
                                                 String label) {
        if (!isClassCoveredByCfg(className, cfg.obfClass, cfg.blackClass)) {
            if (strings.failOnUnprotectedDecryptor) {
                throw new GradleException("[dex-cfg-obf] string ${label} ${className} is outside " +
                        'dexObfuscator.obfClass or excluded by dexObfuscator.blackClass while ' +
                        'stringEncryption.failOnUnprotectedDecryptor=true')
            }
            project.logger.warn("[dex-cfg-obf] string ${label} ${className} is outside " +
                    'dexObfuscator.obfClass or excluded by dexObfuscator.blackClass, so its ' +
                    'decrypt logic will not receive CFG protection')
        }
    }

    private static void warnLegacyCfgDslOnce(Project project,
                                             DexCfgObfuscatorExtension ext) {
        if (ext.consumeLegacyCfgDslWarning()) {
            project.logger.warn('[dex-cfg-obf] legacy top-level CFG DSL is deprecated ' +
                    "(first property: ${ext.firstLegacyCfgPropertyForPlugin()}); move all CFG " +
                    'properties into dexControlFlowObfuscator.dexObfuscator { ... }. The legacy ' +
                    'CFG enabledVariants selector is compatibility-only and has no replacement; ' +
                    'enabled=true applies to every variant that is built.')
        }
    }

    static boolean isClassCoveredByCfg(String className,
                                       Collection<String> includes,
                                       Collection<String> excludes) {
        String normalized = className == null ? '' : className.trim().replace('/', '.')
        if (normalized.isEmpty()) return false
        if ((excludes ?: []).any { Object value -> classPrefixMatches(normalized, value) }) {
            return false
        }
        return (includes ?: []).any { Object value -> classPrefixMatches(normalized, value) }
    }

    private static boolean classPrefixMatches(String className, Object rawPrefix) {
        if (rawPrefix == null) return false
        String prefix = rawPrefix.toString().trim().replace('/', '.')
        while (prefix.endsWith('.')) prefix = prefix.substring(0, prefix.length() - 1)
        return !prefix.isEmpty() && (className == prefix || className.startsWith(prefix + '.')
                || className.startsWith(prefix + '$'))
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

    private static List<File> findDexDirectories(Project project, String variantName,
                                                 Task producer) {
        List<File> dexDirs = []
        producer.outputs.files.files.each { File file ->
            if (file.isDirectory()) dexDirs.add(file)
            else if (file.isFile() && file.name.endsWith('.dex')) dexDirs.add(file.parentFile)
        }
        File conventional = new File(project.buildDir,
                "intermediates/dex/${variantName}/${producer.name}")
        if (conventional.isDirectory()) dexDirs.add(conventional)
        return collapseNestedDexDirs(
                dexDirs.findAll { it != null && it.isDirectory() }
                        .unique { it.canonicalPath })
                .findAll { containsDex(it) }
    }

    /**
     * Debug 的最终 APK 通常由 project/lib/ext 三组 merged DEX 输入组成。字符串门禁只读扫描
     * 全部输入，CFG 仍只改写 primary producer，避免把依赖类纳入混淆范围。
     */
    private static List<File> findStringAuditDexDirectories(Project project,
                                                            String variantCap,
                                                            List<File> primary,
                                                            boolean minified) {
        List<File> roots = new ArrayList<>(primary ?: [])
        // R8 producer 已是 application 的最终、合并后 DEX；扫描 pre-R8 ext/lib 会产生
        // “并未进入 APK 的明文”假阳性，也会无谓拉入额外任务。
        if (minified) {
            return collapseNestedDexDirs(roots.findAll { it != null && it.isDirectory() }
                    .unique { it.canonicalPath }).findAll { containsDex(it) }
        }
        ["mergeExtDex${variantCap}", "mergeLibDex${variantCap}",
         "generate${variantCap}GlobalSynthetics"].each { String name ->
            Task task = project.tasks.findByName(name)
            if (task == null) return
            task.outputs.files.files.each { File file ->
                if (file.isDirectory()) roots.add(file)
                else if (file.isFile() && file.name.endsWith('.dex')) roots.add(file.parentFile)
            }
        }
        return collapseNestedDexDirs(roots.findAll { it != null && it.isDirectory() }
                .unique { it.canonicalPath }).findAll { containsDex(it) }
    }

    private static Task requirePrimaryDexProducer(Project project,
                                                  boolean useR8,
                                                  String r8Name,
                                                  String mergeProjName,
                                                  String mergeDexName,
                                                  String variantName) {
        Task producer = useR8
                ? project.tasks.findByName(r8Name)
                : (project.tasks.findByName(mergeProjName)
                ?: project.tasks.findByName(mergeDexName))
        if (producer == null) {
            throw new GradleException("[dex-cfg-obf] no ${r8Name}, ${mergeProjName}, " +
                    "or ${mergeDexName} task for ${variantName}")
        }
        return producer
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
