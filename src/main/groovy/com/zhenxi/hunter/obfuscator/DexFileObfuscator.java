package com.zhenxi.hunter.obfuscator;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
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
        Opcodes opcodes = Opcodes.getDefault();
        DexBackedDexFile dex = DexBackedDexFile.fromInputStream(
                opcodes, new java.io.BufferedInputStream(new java.io.FileInputStream(dexFile)));

        int dexApi = dex.getOpcodes().api;
        Set<ClassDef> newClasses = new LinkedHashSet<>();
        boolean anyChange = false;

        CfgFlattener flattener = new CfgFlattener(config, logger, stats);

        for (ClassDef classDef : dex.getClasses()) {
            stats.classesScanned++;
            if (!config.shouldProcessClass(classDef.getType())) {
                newClasses.add(classDef);
                continue;
            }

            List<Method> newDirect = new ArrayList<>();
            List<Method> newVirtual = new ArrayList<>();
            boolean classChanged = false;

            for (Method method : classDef.getDirectMethods()) {
                Method m = maybeObfuscate(method, flattener, config, stats);
                if (m != method) {
                    classChanged = true;
                }
                newDirect.add(m);
            }
            for (Method method : classDef.getVirtualMethods()) {
                Method m = maybeObfuscate(method, flattener, config, stats);
                if (m != method) {
                    classChanged = true;
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
            return;
        }

        DexFile out = new ImmutableDexFile(dex.getOpcodes(), newClasses);
        // 先写临时文件再原子替换，避免中途失败破坏原 dex。
        File tmp = new File(dexFile.getParentFile(), dexFile.getName() + ".obf.tmp");
        DexPool pool = new DexPool(dex.getOpcodes());
        for (ClassDef c : out.getClasses()) {
            pool.internClass(c);
        }
        pool.writeTo(new FileDataStore(tmp));
        if (!tmp.renameTo(dexFile)) {
            // renameTo 在跨文件系统会失败，退化为拷贝覆盖。
            java.nio.file.Files.copy(tmp.toPath(), dexFile.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            tmp.delete();
        }
    }

    private static Method maybeObfuscate(Method method,
                                         CfgFlattener flattener,
                                         ObfuscatorConfig config,
                                         ObfuscatorStats stats) {
        MethodImplementation impl = method.getImplementation();
        if (impl == null) {
            return method; // 抽象/native 方法，无字节码
        }
        stats.methodsScanned++;

        MethodImplementation obf = flattener.flatten(method, impl);
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
