package com.hunter.dexcfgobf.string;

import com.hunter.dexcfgobf.ObfuscatorStats;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** 完成 JVM 字节码插桩后的无敏感明文统计快照。 */
public final class StringEncryptionSnapshot {
    public final boolean enabled;
    public final String mode;
    public final int classesVisited;
    public final int classesModified;
    public final int constantsEncrypted;
    public final int constantsSkipped;
    public final int skippedWhitespace;
    public final int skippedTooLarge;
    public final int skippedInvalidUnicode;
    public final int skippedFiltered;
    public final int unsupportedConstants;
    public final int identityCiphertexts;
    /** 仅供最终产物内存校验；不会写入报告。 */
    public final Set<String> encryptedPlaintextHashes;
    /** 本轮 ASM 实际访问过的原始分类名，包括访问后已无需加密字符串的类。 */
    public final Set<String> visitedOriginalClassNames;
    /** 本轮确实插入过解密桥调用的原始点分类名。 */
    public final Set<String> modifiedOriginalClassNames;
    /**
     * 每个原始 owner 实际保护的明文摘要。最终 DEX 门禁必须同时命中 owner
     * 和摘要，避免其他类重用通用字符串时误报。键值均为防御性不可变快照。
     */
    public final Map<String, Set<String>> encryptedPlaintextHashesByOriginalClass;
    /** Exact original method key ({@code ownerInternal->name(descriptor)}) to hashes. */
    public final Map<String, Set<String>> encryptedPlaintextHashesByOriginalMethod;
    /**
     * Exact original field key ({@code ownerInternal->name}) to provenance hashes. Static
     * ConstantValue rewrites are gated at the corresponding {@code owner-><clinit>()V} entry in
     * {@link #encryptedPlaintextHashesByOriginalMethod}; this map is not a final-Dex field target.
     */
    public final Map<String, Set<String>> encryptedPlaintextHashesByOriginalField;

    StringEncryptionSnapshot(boolean enabled, String mode, int classesVisited, int classesModified,
                             int constantsEncrypted, int constantsSkipped, int skippedWhitespace,
                             int skippedTooLarge, int skippedInvalidUnicode, int skippedFiltered,
                             int unsupportedConstants,
                             int identityCiphertexts, Set<String> encryptedPlaintextHashes,
                             Set<String> visitedOriginalClassNames,
                             Map<String, Set<String>> encryptedPlaintextHashesByOriginalClass,
                             Map<String, Set<String>> encryptedPlaintextHashesByOriginalMethod,
                             Map<String, Set<String>> encryptedPlaintextHashesByOriginalField) {
        this.enabled = enabled;
        this.mode = mode;
        this.classesVisited = classesVisited;
        this.classesModified = classesModified;
        this.constantsEncrypted = constantsEncrypted;
        this.constantsSkipped = constantsSkipped;
        this.skippedWhitespace = skippedWhitespace;
        this.skippedTooLarge = skippedTooLarge;
        this.skippedInvalidUnicode = skippedInvalidUnicode;
        this.skippedFiltered = skippedFiltered;
        this.unsupportedConstants = unsupportedConstants;
        this.identityCiphertexts = identityCiphertexts;
        this.encryptedPlaintextHashes = Collections.unmodifiableSet(
                new TreeSet<>(encryptedPlaintextHashes));
        this.visitedOriginalClassNames = Collections.unmodifiableSet(
                new TreeSet<>(visitedOriginalClassNames));
        Map<String, Set<String>> byOwner = new LinkedHashMap<>();
        for (String owner : new TreeSet<>(encryptedPlaintextHashesByOriginalClass.keySet())) {
            byOwner.put(owner, Collections.unmodifiableSet(
                    new TreeSet<>(encryptedPlaintextHashesByOriginalClass.get(owner))));
        }
        this.encryptedPlaintextHashesByOriginalClass = Collections.unmodifiableMap(byOwner);
        this.modifiedOriginalClassNames = Collections.unmodifiableSet(
                new TreeSet<>(byOwner.keySet()));
        this.encryptedPlaintextHashesByOriginalMethod = immutableNestedMap(
                encryptedPlaintextHashesByOriginalMethod);
        this.encryptedPlaintextHashesByOriginalField = immutableNestedMap(
                encryptedPlaintextHashesByOriginalField);
    }

    private static Map<String, Set<String>> immutableNestedMap(Map<String, Set<String>> source) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        for (String key : new TreeSet<>(source.keySet())) {
            result.put(key, Collections.unmodifiableSet(new TreeSet<>(source.get(key))));
        }
        return Collections.unmodifiableMap(result);
    }

    public void applyTo(ObfuscatorStats stats) {
        stats.stringEncryptionEnabled = enabled;
        stats.stringEncryptionMode = mode;
        stats.stringCoverageStatus = "FULL";
        stats.stringClassesVisited = classesVisited;
        stats.stringClassesModified = classesModified;
        stats.stringConstantsEncrypted = constantsEncrypted;
        stats.stringConstantsSkipped = constantsSkipped;
        stats.stringSkippedWhitespace = skippedWhitespace;
        stats.stringSkippedTooLarge = skippedTooLarge;
        stats.stringSkippedInvalidUnicode = skippedInvalidUnicode;
        stats.stringSkippedFiltered = skippedFiltered;
        stats.stringUnsupportedConstants = unsupportedConstants;
        stats.stringIdentityCiphertexts = identityCiphertexts;
        stats.stringPlaintextHashesTracked = encryptedPlaintextHashes.size();
    }
}
