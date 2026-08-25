package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.analysis.ClassPath;
import com.android.tools.smali.dexlib2.analysis.DexClassProvider;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 单个 .dex 的读取 -> 逐方法混淆 -> 回写。
 * 使用 dexlib2 的不可变模型重建 DexFile；只替换被混淆方法的 implementation，
 * 其余类/方法原样透传，最大限度保持产物稳定。
 */
final class DexFileObfuscator {

    static void obfuscateSingleDex(File dexFile,
                                   ObfuscatorConfig config,
                                   ObfuscatorLogger logger,
                                   ObfuscatorStats stats) throws Exception {
        long originalBytes = dexFile.length();
        stats.originalDexBytes += originalBytes;
        DexBackedDexFile dex;
        try (java.io.BufferedInputStream input = new java.io.BufferedInputStream(
                new java.io.FileInputStream(dexFile))) {
            // null 让 dexlib2 根据文件头（dex.035/037/038/039...）选择指令表。
            // 固定使用 Opcodes.getDefault() 会按 API 20 解析，新版 DEX 中的
            // invoke-polymorphic/invoke-custom 会被误识别为旧 odex quick 指令。
            dex = DexBackedDexFile.fromInputStream(null, input);
        }
        Set<ClassDef> newClasses = new LinkedHashSet<>();
        boolean anyChange = false;

        CfgFlattener flattener = new CfgFlattener(config, logger, stats);
        VerifierTypeSeparator typeSeparator = null;
        if (config.enableRegisterTypeSeparation) {
            ClassPath classPath = new ClassPath(java.util.Collections.singletonList(
                    new DexClassProvider(dex)), false, ClassPath.NOT_ART);
            typeSeparator = new VerifierTypeSeparator(classPath, config);
        }

        for (ClassDef classDef : dex.getClasses()) {
            stats.classesScanned++;
            if (!config.shouldProcessClass(classDef.getType())) {
                if (config.refuseAlreadyObfuscatedInput) {
                    stats.methodsSkippedAlreadyObfuscated += countObfuscationMarkers(classDef);
                }
                newClasses.add(classDef);
                continue;
            }

            List<Method> newDirect = new ArrayList<>();
            List<Method> newVirtual = new ArrayList<>();
            boolean classChanged = false;

            for (Method method : classDef.getDirectMethods()) {
                if (!config.shouldProcessMethod(classDef.getType(), method.getName())) {
                    if (method.getImplementation() != null) stats.methodsSkippedNotIncluded++;
                    newDirect.add(method);
                    continue;
                }
                boolean required = isRequiredResolvedMethod(config, method);
                if (required && method.getImplementation() != null) {
                    stats.cfgRequiredMethodsScanned++;
                }
                Method m = maybeObfuscate(dexFile.getName(), method, flattener,
                        typeSeparator, config, stats);
                if (m != method) {
                    classChanged = true;
                    if (required) stats.cfgRequiredMethodsObfuscated++;
                }
                newDirect.add(m);
            }
            for (Method method : classDef.getVirtualMethods()) {
                if (!config.shouldProcessMethod(classDef.getType(), method.getName())) {
                    if (method.getImplementation() != null) stats.methodsSkippedNotIncluded++;
                    newVirtual.add(method);
                    continue;
                }
                boolean required = isRequiredResolvedMethod(config, method);
                if (required && method.getImplementation() != null) {
                    stats.cfgRequiredMethodsScanned++;
                }
                Method m = maybeObfuscate(dexFile.getName(), method, flattener,
                        typeSeparator, config, stats);
                if (m != method) {
                    classChanged = true;
                    if (required) stats.cfgRequiredMethodsObfuscated++;
                }
                newVirtual.add(m);
            }

            if (!classChanged) {
                newClasses.add(classDef);
                continue;
            }
            anyChange = true;
            newClasses.add(new ImmutableClassDef(
                    classDef.getType(),
                    classDef.getAccessFlags(),
                    classDef.getSuperclass(),
                    classDef.getInterfaces(),
                    classDef.getSourceFile(),
                    classDef.getAnnotations(),
                    classDef.getStaticFields(),
                    classDef.getInstanceFields(),
                    newDirect,
                    newVirtual));
        }

        stats.dexProcessed++;
        if (!anyChange) {
            if (config.verifyStructure) {
                DexStructuralVerifier.verify(dexFile);
                stats.dexVerified++;
            }
            stats.outputDexBytes += dexFile.length();
            return;
        }

        DexFile out = new ImmutableDexFile(dex.getOpcodes(), newClasses);
        // 先写临时文件再原子替换，避免中途失败破坏原 dex。
        File tmp = new File(dexFile.getParentFile(), dexFile.getName() + ".obf.tmp");
        DexPool pool = new SourceFileAwareDexPool(dex.getOpcodes());
        for (ClassDef c : out.getClasses()) {
            pool.internClass(c);
        }
        pool.writeTo(new FileDataStore(tmp));
        if (config.verifyStructure) {
            DexStructuralVerifier.verify(tmp);
            stats.dexVerified++;
        }
        if (!tmp.renameTo(dexFile)) {
            // renameTo 在跨文件系统会失败，退化为拷贝覆盖。
            java.nio.file.Files.copy(tmp.toPath(), dexFile.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            tmp.delete();
        }
        stats.outputDexBytes += dexFile.length();
    }

    /** Marker refusal must be artifact-wide, independent of the current include/exclude scope. */
    private static int countObfuscationMarkers(ClassDef classDef) {
        int count = 0;
        for (Method method : classDef.getDirectMethods()) {
            if (ObfuscationMarker.hasV1(method.getImplementation())) count++;
        }
        for (Method method : classDef.getVirtualMethods()) {
            if (ObfuscationMarker.hasV1(method.getImplementation())) count++;
        }
        return count;
    }

    private static boolean isRequiredResolvedMethod(ObfuscatorConfig config, Method method) {
        return config.requiredResolvedIncludeMethods.contains(
                ObfuscatorConfig.normalizeClassName(method.getDefiningClass())
                        + "->" + method.getName());
    }

    private static Method maybeObfuscate(String dexName,
                                         Method method,
                                         CfgFlattener flattener,
                                         VerifierTypeSeparator typeSeparator,
                                         ObfuscatorConfig config,
                                         ObfuscatorStats stats) {
        MethodImplementation impl = method.getImplementation();
        if (impl == null) {
            return method; // 抽象/native 方法，无字节码
        }
        stats.methodsScanned++;

        VerifierTypeSeparator.Result separated = typeSeparator == null
                ? null : typeSeparator.separate(method);
        MethodImplementation candidate = separated == null ? impl : separated.implementation;
        // Capture line/source provenance before verifier register separation rebuilds the method.
        // Separation and register shifting retain one output instruction per input instruction, so
        // this original index map remains valid through the later CFG transform.
        DebugPositionMap debugPositions = DebugPositionMap.capture(impl);
        MethodImplementation obf = flattener.flatten(method, candidate, debugPositions,
                separated != null, separated == null ? 0 : separated.addedRegisters);
        TransformationOutcome outcome = flattener.getLastOutcome();
        if (outcome == null) {
            throw new IllegalStateException("missing transformation outcome for "
                    + method.getDefiningClass() + "->" + method.getName());
        }
        stats.methodReports.add(MethodReport.of(dexName, method, outcome, impl, obf));
        if (obf == null) {
            return method; // 不满足安全前提，保持原样
        }
        stats.methodsObfuscated++;
        return new ImmutableMethod(
                method.getDefiningClass(),
                method.getName(),
                method.getParameters(),
                method.getReturnType(),
                method.getAccessFlags(),
                method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                ImmutableMethodImplementation.of(obf));
    }
}
