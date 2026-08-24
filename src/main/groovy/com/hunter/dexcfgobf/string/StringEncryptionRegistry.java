package com.hunter.dexcfgobf.string;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.Set;

/** AGP ASM visitor 参数只能序列化简单值；自定义算法对象保存在当前 Gradle 进程的 registry。 */
public final class StringEncryptionRegistry {
    private static final ConcurrentMap<String, StringEncryptionContext> CONTEXTS =
            new ConcurrentHashMap<>();

    public static void register(String key, StringEncryptionContext context) {
        if (key == null || key.isEmpty() || context == null) {
            throw new IllegalArgumentException("string encryption registry key/context must not be empty");
        }
        CONTEXTS.put(key, context);
    }

    public static StringEncryptionContext require(String key) {
        StringEncryptionContext context = CONTEXTS.get(key);
        if (context == null) {
            throw new IllegalStateException("string encryption context unavailable for " + key
                    + "; rerun without Gradle configuration cache when using custom algorithm objects");
        }
        return context;
    }

    public static StringEncryptionSnapshot snapshot(String key) {
        return require(key).snapshot();
    }

    public static String bridgeInternalName(String key) {
        return require(key).getBridgeInternalName();
    }

    public static Set<String> requiredDecryptorOriginalMethodKeys(String key) {
        return require(key).getRequiredDecryptorOriginalMethodKeys();
    }

    public static Set<String> discoverRequiredDecryptorOriginalMethodKeys(
            String key, Collection<File> outputs) throws IOException {
        return require(key).discoverRequiredDecryptorOriginalMethodKeys(outputs);
    }

    public static void remove(String key) {
        if (key != null) CONTEXTS.remove(key);
    }

    private StringEncryptionRegistry() {}
}
