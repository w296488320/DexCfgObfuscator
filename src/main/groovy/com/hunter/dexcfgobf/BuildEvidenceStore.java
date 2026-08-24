package com.hunter.dexcfgobf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Versioned, integrity-checked persistence for evidence needed by incremental build gates.
 *
 * <p>The caller owns the location and should place files below {@code build/intermediates}; this
 * class deliberately does not write reports. A missing file or a well-formed record for different
 * artifact/transform digests is unavailable ({@link Optional#empty()}). A malformed, truncated,
 * checksum-invalid, wrong-kind, or unsupported-version record throws
 * {@link EvidenceFormatException} so stale evidence is never silently trusted.</p>
 */
public final class BuildEvidenceStore {
    private static final int MAGIC = 0x44434f45; // "DCOE"
    private static final int FORMAT_VERSION = 6;
    private static final int TYPE_CFG = 1;
    private static final int TYPE_STRING = 2;
    private static final int TYPE_CFG_PENDING = 3;
    private static final int CHECKSUM_BYTES = 32;
    private static final int HEADER_BYTES = Integer.BYTES + Integer.BYTES + 1 + Integer.BYTES;
    private static final int MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;
    private static final int MAX_STRING_BYTES = 1024 * 1024;
    private static final int MAX_METHOD_REPORTS = 250_000;
    private static final int MAX_PLAINTEXT_HASHES = 1_000_000;
    private static final int MAX_STRING_OWNER_CLASSES = 1_000_000;

    private BuildEvidenceStore() {
    }

    /** Defensive stats snapshot for evidence that must be committed after a later artifact gate. */
    public static ObfuscatorStats snapshotStats(ObfuscatorStats source) {
        return copyStats(Objects.requireNonNull(source, "source"));
    }

    /** Stable per-DEX-directory evidence filename below the supplied intermediates root. */
    public static File cfgEvidenceFile(File evidenceRoot, File dexDir) throws IOException {
        Objects.requireNonNull(evidenceRoot, "evidenceRoot");
        Objects.requireNonNull(dexDir, "dexDir");
        return new File(evidenceRoot, sha256Hex(dexDir.getCanonicalPath()) + ".cfg.evidence");
    }

    /** Stable per-DEX-directory transaction marker used before an in-place CFG rewrite. */
    public static File cfgPendingFile(File evidenceRoot, File dexDir) throws IOException {
        Objects.requireNonNull(evidenceRoot, "evidenceRoot");
        Objects.requireNonNull(dexDir, "dexDir");
        return new File(evidenceRoot, sha256Hex(dexDir.getCanonicalPath()) + ".cfg.pending");
    }

    /** Stable file used as an OS-level cross-process lock for one DEX directory transaction. */
    public static File cfgLockFile(File evidenceRoot, File dexDir) throws IOException {
        Objects.requireNonNull(evidenceRoot, "evidenceRoot");
        Objects.requireNonNull(dexDir, "dexDir");
        return new File(evidenceRoot, sha256Hex(dexDir.getCanonicalPath()) + ".cfg.lock");
    }

    /** Stable per-variant string evidence filename below the supplied intermediates root. */
    public static File stringEvidenceFile(File evidenceRoot, String variantName) {
        Objects.requireNonNull(evidenceRoot, "evidenceRoot");
        requireExpectedKey(variantName, "variantName");
        return new File(evidenceRoot, sha256Hex(variantName) + ".string.evidence");
    }

    public static void writeCfg(File evidenceFile, String postFingerprint,
                                String cfgTransformDigest, ObfuscatorStats stats)
            throws IOException {
        requireExpectedKey(postFingerprint, "postFingerprint");
        requireExpectedKey(cfgTransformDigest, "cfgTransformDigest");
        Objects.requireNonNull(stats, "stats");

        byte[] payload = encodePayload(out -> {
            writeString(out, postFingerprint, "postFingerprint");
            writeString(out, cfgTransformDigest, "cfgTransformDigest");
            writeStats(out, stats);
        });
        writeRecord(evidenceFile, TYPE_CFG, payload);
    }

    public static Optional<CfgEvidence> readCfg(File evidenceFile, String expectedPostFingerprint,
                                                 String expectedCfgTransformDigest)
            throws IOException {
        requireExpectedKey(expectedPostFingerprint, "expectedPostFingerprint");
        requireExpectedKey(expectedCfgTransformDigest, "expectedCfgTransformDigest");
        Optional<CfgEvidence> evidence = readCfg(evidenceFile);
        if (!evidence.isPresent()) return evidence;
        CfgEvidence value = evidence.get();
        if (!expectedPostFingerprint.equals(value.getPostFingerprint())
                || !expectedCfgTransformDigest.equals(value.getCfgTransformDigest())) {
            return Optional.empty();
        }
        return evidence;
    }

    /** Reads a valid CFG record without accepting it for any particular artifact/configuration. */
    public static Optional<CfgEvidence> readCfg(File evidenceFile) throws IOException {
        EvidenceRecord record = readRecord(evidenceFile, TYPE_CFG);
        if (record == null) return Optional.empty();

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(record.payload))) {
            String postFingerprint = readRequiredString(in, "postFingerprint");
            String transformDigest = readRequiredString(in, "cfgTransformDigest");
            ObfuscatorStats stats = readStats(in, record.version);
            requirePayloadExhausted(in);
            return Optional.of(new CfgEvidence(postFingerprint, transformDigest, stats));
        } catch (EvidenceFormatException e) {
            throw e;
        } catch (EOFException e) {
            throw new EvidenceFormatException("Truncated CFG build evidence payload", e);
        }
    }

    /**
     * Persists the exact pre-transform artifact/configuration before touching producer DEX.
     * A surviving marker whose fingerprint no longer matches means a previous transaction may
     * have committed DEX without committing its evidence and must therefore fail closed.
     */
    public static void writeCfgPending(File pendingFile, String preFingerprint,
                                       String cfgTransformDigest) throws IOException {
        requireExpectedKey(preFingerprint, "preFingerprint");
        requireExpectedKey(cfgTransformDigest, "cfgTransformDigest");
        byte[] payload = encodePayload(out -> {
            writeString(out, preFingerprint, "preFingerprint");
            writeString(out, cfgTransformDigest, "cfgTransformDigest");
        });
        writeRecord(pendingFile, TYPE_CFG_PENDING, payload);
    }

    public static Optional<CfgPendingEvidence> readCfgPending(File pendingFile)
            throws IOException {
        EvidenceRecord record = readRecord(pendingFile, TYPE_CFG_PENDING);
        if (record == null) return Optional.empty();
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(record.payload))) {
            String preFingerprint = readRequiredString(in, "preFingerprint");
            String transformDigest = readRequiredString(in, "cfgTransformDigest");
            requirePayloadExhausted(in);
            return Optional.of(new CfgPendingEvidence(preFingerprint, transformDigest));
        } catch (EvidenceFormatException e) {
            throw e;
        } catch (EOFException e) {
            throw new EvidenceFormatException("Truncated CFG pending evidence payload", e);
        }
    }

    public static void writeString(File evidenceFile, String auditFingerprint,
                                   String stringTransformDigest, ObfuscatorStats stats,
                                   Set<String> plaintextSha256,
                                   Map<String, ? extends Set<String>> plaintextSha256ByOriginalClass,
                                   Map<String, ? extends Set<String>> plaintextSha256ByOriginalMethod,
                                   Map<String, ? extends Set<String>> plaintextSha256ByOriginalField)
            throws IOException {
        requireExpectedKey(auditFingerprint, "auditFingerprint");
        requireExpectedKey(stringTransformDigest, "stringTransformDigest");
        Objects.requireNonNull(stats, "stats");
        Set<String> normalizedHashes = normalizePlaintextHashes(plaintextSha256);
        Map<String, Set<String>> normalizedOwnerHashes = normalizeOwnerHashes(
                plaintextSha256ByOriginalClass, normalizedHashes);
        Map<String, Set<String>> normalizedMethodHashes = normalizeMemberHashes(
                plaintextSha256ByOriginalMethod, normalizedHashes, true);
        Map<String, Set<String>> normalizedFieldHashes = normalizeMemberHashes(
                plaintextSha256ByOriginalField, normalizedHashes, false);
        Set<String> siteHashes = new TreeSet<>();
        for (Set<String> hashes : normalizedMethodHashes.values()) siteHashes.addAll(hashes);
        for (Set<String> hashes : normalizedFieldHashes.values()) siteHashes.addAll(hashes);
        if (!siteHashes.equals(normalizedHashes)) {
            throw new IllegalArgumentException(
                    "method/field string scopes must cover every plaintextSha256 value");
        }

        byte[] payload = encodePayload(out -> {
            writeString(out, auditFingerprint, "auditFingerprint");
            writeString(out, stringTransformDigest, "stringTransformDigest");
            writeStats(out, stats);
            out.writeInt(normalizedHashes.size());
            for (String hash : normalizedHashes) writeString(out, hash, "plaintextSha256");
            out.writeInt(normalizedOwnerHashes.size());
            for (Map.Entry<String, Set<String>> entry : normalizedOwnerHashes.entrySet()) {
                writeString(out, entry.getKey(), "stringOriginalOwner");
                out.writeInt(entry.getValue().size());
                for (String hash : entry.getValue()) {
                    writeString(out, hash, "ownerPlaintextSha256");
                }
            }
            writeNestedHashMap(out, normalizedMethodHashes, "stringOriginalMethod");
            writeNestedHashMap(out, normalizedFieldHashes, "stringOriginalField");
        });
        writeRecord(evidenceFile, TYPE_STRING, payload);
    }

    /** Package-private compatibility fixture writer; production callers must write current scope. */
    static void writeLegacyV2StringForTest(File evidenceFile, String auditFingerprint,
                                           String stringTransformDigest, ObfuscatorStats stats,
                                           Set<String> plaintextSha256) throws IOException {
        requireExpectedKey(auditFingerprint, "auditFingerprint");
        requireExpectedKey(stringTransformDigest, "stringTransformDigest");
        Objects.requireNonNull(stats, "stats");
        Set<String> normalizedHashes = normalizePlaintextHashes(plaintextSha256);
        byte[] payload = encodePayload(out -> {
            writeString(out, auditFingerprint, "auditFingerprint");
            writeString(out, stringTransformDigest, "stringTransformDigest");
            writeStats(out, stats, 2);
            out.writeInt(normalizedHashes.size());
            for (String hash : normalizedHashes) writeString(out, hash, "plaintextSha256");
        });
        writeRecord(evidenceFile, TYPE_STRING, payload, 2);
    }

    /** Package-private v3 compatibility fixture writer for skip-reason migration tests. */
    static void writeLegacyV3StringForTest(
            File evidenceFile, String auditFingerprint, String stringTransformDigest,
            ObfuscatorStats stats, Set<String> plaintextSha256,
            Map<String, ? extends Set<String>> plaintextSha256ByOriginalClass,
            Map<String, ? extends Set<String>> plaintextSha256ByOriginalMethod,
            Map<String, ? extends Set<String>> plaintextSha256ByOriginalField) throws IOException {
        requireExpectedKey(auditFingerprint, "auditFingerprint");
        requireExpectedKey(stringTransformDigest, "stringTransformDigest");
        Objects.requireNonNull(stats, "stats");
        Set<String> normalizedHashes = normalizePlaintextHashes(plaintextSha256);
        Map<String, Set<String>> normalizedOwnerHashes = normalizeOwnerHashes(
                plaintextSha256ByOriginalClass, normalizedHashes);
        Map<String, Set<String>> normalizedMethodHashes = normalizeMemberHashes(
                plaintextSha256ByOriginalMethod, normalizedHashes, true);
        Map<String, Set<String>> normalizedFieldHashes = normalizeMemberHashes(
                plaintextSha256ByOriginalField, normalizedHashes, false);
        Set<String> siteHashes = new TreeSet<>();
        for (Set<String> hashes : normalizedMethodHashes.values()) siteHashes.addAll(hashes);
        for (Set<String> hashes : normalizedFieldHashes.values()) siteHashes.addAll(hashes);
        if (!siteHashes.equals(normalizedHashes)) {
            throw new IllegalArgumentException(
                    "method/field string scopes must cover every plaintextSha256 value");
        }
        byte[] payload = encodePayload(out -> {
            writeString(out, auditFingerprint, "auditFingerprint");
            writeString(out, stringTransformDigest, "stringTransformDigest");
            writeStats(out, stats, 3);
            out.writeInt(normalizedHashes.size());
            for (String hash : normalizedHashes) writeString(out, hash, "plaintextSha256");
            out.writeInt(normalizedOwnerHashes.size());
            for (Map.Entry<String, Set<String>> entry : normalizedOwnerHashes.entrySet()) {
                writeString(out, entry.getKey(), "stringOriginalOwner");
                out.writeInt(entry.getValue().size());
                for (String hash : entry.getValue()) {
                    writeString(out, hash, "ownerPlaintextSha256");
                }
            }
            writeNestedHashMap(out, normalizedMethodHashes, "stringOriginalMethod");
            writeNestedHashMap(out, normalizedFieldHashes, "stringOriginalField");
        });
        writeRecord(evidenceFile, TYPE_STRING, payload, 3);
    }

    public static Optional<StringEvidence> readString(File evidenceFile,
                                                       String expectedAuditFingerprint,
                                                       String expectedStringTransformDigest)
            throws IOException {
        requireExpectedKey(expectedAuditFingerprint, "expectedAuditFingerprint");
        requireExpectedKey(expectedStringTransformDigest, "expectedStringTransformDigest");
        Optional<StringEvidence> evidence = readString(evidenceFile);
        if (!evidence.isPresent()) return evidence;
        StringEvidence value = evidence.get();
        if (!expectedAuditFingerprint.equals(value.getAuditFingerprint())
                || !expectedStringTransformDigest.equals(value.getStringTransformDigest())) {
            return Optional.empty();
        }
        return evidence;
    }

    /**
     * Reads valid string evidence without accepting it for a particular artifact/configuration.
     * Callers use this only to carry the prior hash set across an incremental artifact change;
     * the transform digest must still be checked before those hashes are trusted.
     */
    public static Optional<StringEvidence> readString(File evidenceFile) throws IOException {
        EvidenceRecord record = readRecord(evidenceFile, TYPE_STRING);
        if (record == null) return Optional.empty();

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(record.payload))) {
            String auditFingerprint = readRequiredString(in, "auditFingerprint");
            String transformDigest = readRequiredString(in, "stringTransformDigest");
            ObfuscatorStats stats = readStats(in, record.version);
            int hashCount = readBoundedCount(in, "plaintext SHA-256 count", MAX_PLAINTEXT_HASHES);
            Set<String> hashes = new TreeSet<>();
            for (int i = 0; i < hashCount; i++) {
                String hash = readRequiredString(in, "plaintextSha256").toLowerCase(Locale.ROOT);
                if (!isSha256(hash)) {
                    throw new EvidenceFormatException("Invalid plaintext SHA-256 at index " + i);
                }
                if (!hashes.add(hash)) {
                    throw new EvidenceFormatException("Duplicate plaintext SHA-256 at index " + i);
                }
            }
            Map<String, Set<String>> ownerHashes = new TreeMap<>();
            Map<String, Set<String>> methodHashes = new TreeMap<>();
            Map<String, Set<String>> fieldHashes = new TreeMap<>();
            boolean ownerScopeAvailable = record.version >= 3;
            if (ownerScopeAvailable) {
                int ownerCount = readBoundedCount(in, "string original owner count",
                        MAX_STRING_OWNER_CLASSES);
                for (int i = 0; i < ownerCount; i++) {
                    String owner = readRequiredString(in, "stringOriginalOwner");
                    String normalizedOwner = normalizeOriginalClassName(owner);
                    if (normalizedOwner.isEmpty() || !owner.equals(normalizedOwner)) {
                        throw new EvidenceFormatException(
                                "Non-canonical string original owner at index " + i);
                    }
                    int ownerHashCount = readBoundedCount(in,
                            "owner plaintext SHA-256 count", MAX_PLAINTEXT_HASHES);
                    if (ownerHashCount == 0) {
                        throw new EvidenceFormatException(
                                "String original owner has no protected hashes at index " + i);
                    }
                    Set<String> values = new TreeSet<>();
                    for (int j = 0; j < ownerHashCount; j++) {
                        String hash = readRequiredString(in, "ownerPlaintextSha256")
                                .toLowerCase(Locale.ROOT);
                        if (!isSha256(hash) || !hashes.contains(hash)) {
                            throw new EvidenceFormatException(
                                    "Invalid owner plaintext SHA-256 at index " + i + ":" + j);
                        }
                        if (!values.add(hash)) {
                            throw new EvidenceFormatException(
                                    "Duplicate owner plaintext SHA-256 at index " + i + ":" + j);
                        }
                    }
                    if (ownerHashes.put(normalizedOwner, values) != null) {
                        throw new EvidenceFormatException(
                                "Duplicate string original owner at index " + i);
                    }
                }
                Set<String> scopedHashes = new TreeSet<>();
                for (Set<String> values : ownerHashes.values()) scopedHashes.addAll(values);
                if (!scopedHashes.equals(hashes)) {
                    throw new EvidenceFormatException(
                            "String evidence owner scope does not cover every plaintext SHA-256");
                }
                methodHashes.putAll(readNestedHashMap(in, hashes,
                        "string original method", true));
                fieldHashes.putAll(readNestedHashMap(in, hashes,
                        "string original field", false));
                Set<String> siteHashes = new TreeSet<>();
                for (Set<String> values : methodHashes.values()) siteHashes.addAll(values);
                for (Set<String> values : fieldHashes.values()) siteHashes.addAll(values);
                if (!siteHashes.equals(hashes)) {
                    throw new EvidenceFormatException(
                            "String evidence member scope does not cover every plaintext SHA-256");
                }
            }
            requirePayloadExhausted(in);
            return Optional.of(new StringEvidence(auditFingerprint, transformDigest, stats, hashes,
                    ownerHashes, methodHashes, fieldHashes, ownerScopeAvailable, record.version));
        } catch (EvidenceFormatException e) {
            throw e;
        } catch (EOFException e) {
            throw new EvidenceFormatException("Truncated string build evidence payload", e);
        }
    }

    /** A checked failure that means an existing evidence file must not be trusted. */
    public static final class EvidenceFormatException extends IOException {
        public EvidenceFormatException(String message) {
            super(message);
        }

        public EvidenceFormatException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Immutable CFG evidence snapshot. Returned stats are defensive copies. */
    public static final class CfgEvidence {
        private final String postFingerprint;
        private final String cfgTransformDigest;
        private final ObfuscatorStats stats;

        private CfgEvidence(String postFingerprint, String cfgTransformDigest,
                            ObfuscatorStats stats) {
            this.postFingerprint = postFingerprint;
            this.cfgTransformDigest = cfgTransformDigest;
            this.stats = copyStats(stats);
        }

        public String getPostFingerprint() {
            return postFingerprint;
        }

        public String getCfgTransformDigest() {
            return cfgTransformDigest;
        }

        public ObfuscatorStats getStats() {
            return copyStats(stats);
        }
    }

    /** Immutable pre-transform transaction marker. */
    public static final class CfgPendingEvidence {
        private final String preFingerprint;
        private final String cfgTransformDigest;

        private CfgPendingEvidence(String preFingerprint, String cfgTransformDigest) {
            this.preFingerprint = preFingerprint;
            this.cfgTransformDigest = cfgTransformDigest;
        }

        public String getPreFingerprint() {
            return preFingerprint;
        }

        public String getCfgTransformDigest() {
            return cfgTransformDigest;
        }
    }

    /** Immutable string-audit evidence snapshot. Plaintext values themselves are never stored. */
    public static final class StringEvidence {
        private final String auditFingerprint;
        private final String stringTransformDigest;
        private final ObfuscatorStats stats;
        private final Set<String> plaintextSha256;
        private final Map<String, Set<String>> plaintextSha256ByOriginalClass;
        private final Map<String, Set<String>> plaintextSha256ByOriginalMethod;
        private final Map<String, Set<String>> plaintextSha256ByOriginalField;
        private final boolean ownerScopeAvailable;
        private final int formatVersion;

        private StringEvidence(String auditFingerprint, String stringTransformDigest,
                               ObfuscatorStats stats, Set<String> plaintextSha256,
                               Map<String, Set<String>> plaintextSha256ByOriginalClass,
                               Map<String, Set<String>> plaintextSha256ByOriginalMethod,
                               Map<String, Set<String>> plaintextSha256ByOriginalField,
                               boolean ownerScopeAvailable, int formatVersion) {
            this.auditFingerprint = auditFingerprint;
            this.stringTransformDigest = stringTransformDigest;
            this.stats = copyStats(stats);
            this.plaintextSha256 = Collections.unmodifiableSet(
                    new LinkedHashSet<>(new TreeSet<>(plaintextSha256)));
            Map<String, Set<String>> ownerHashes = new LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> entry
                    : new TreeMap<>(plaintextSha256ByOriginalClass).entrySet()) {
                ownerHashes.put(entry.getKey(), Collections.unmodifiableSet(
                        new LinkedHashSet<>(new TreeSet<>(entry.getValue()))));
            }
            this.plaintextSha256ByOriginalClass = Collections.unmodifiableMap(ownerHashes);
            this.plaintextSha256ByOriginalMethod = immutableNestedMap(
                    plaintextSha256ByOriginalMethod);
            this.plaintextSha256ByOriginalField = immutableNestedMap(
                    plaintextSha256ByOriginalField);
            this.ownerScopeAvailable = ownerScopeAvailable;
            this.formatVersion = formatVersion;
        }

        public String getAuditFingerprint() {
            return auditFingerprint;
        }

        public String getStringTransformDigest() {
            return stringTransformDigest;
        }

        public ObfuscatorStats getStats() {
            return copyStats(stats);
        }

        public Set<String> getPlaintextSha256() {
            return plaintextSha256;
        }

        public Map<String, Set<String>> getPlaintextSha256ByOriginalClass() {
            return plaintextSha256ByOriginalClass;
        }

        public Set<String> getModifiedOriginalClassNames() {
            return plaintextSha256ByOriginalClass.keySet();
        }

        public Map<String, Set<String>> getPlaintextSha256ByOriginalMethod() {
            return plaintextSha256ByOriginalMethod;
        }

        public Map<String, Set<String>> getPlaintextSha256ByOriginalField() {
            return plaintextSha256ByOriginalField;
        }

        /** False for valid v1/v2 records: callers must require a clean rebuild before scoped gates. */
        public boolean hasOwnerScope() {
            return ownerScopeAvailable;
        }

        public boolean hasMemberScope() {
            return ownerScopeAvailable;
        }

        public int getFormatVersion() {
            return formatVersion;
        }

        public boolean hasSkipReasonStats() {
            return formatVersion >= 4;
        }

        public String getCoverageStatus() {
            return stats.stringCoverageStatus;
        }
    }

    private interface PayloadWriter {
        void write(DataOutputStream out) throws IOException;
    }

    private static byte[] encodePayload(PayloadWriter writer) throws IOException {
        BoundedOutputStream bounded = new BoundedOutputStream(MAX_PAYLOAD_BYTES);
        try (DataOutputStream out = new DataOutputStream(bounded)) {
            writer.write(out);
            out.flush();
        }
        return bounded.toByteArray();
    }

    private static void writeRecord(File evidenceFile, int type, byte[] payload) throws IOException {
        writeRecord(evidenceFile, type, payload, FORMAT_VERSION);
    }

    private static void writeRecord(File evidenceFile, int type, byte[] payload, int version)
            throws IOException {
        Objects.requireNonNull(evidenceFile, "evidenceFile");
        if (payload.length > MAX_PAYLOAD_BYTES) {
            throw new IOException("Build evidence payload exceeds " + MAX_PAYLOAD_BYTES + " bytes");
        }
        Path target = evidenceFile.toPath().toAbsolutePath().normalize();
        Path parent = target.getParent();
        if (parent == null) throw new IOException("Build evidence file has no parent: " + evidenceFile);
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".build-evidence-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
                 DataOutputStream out = new DataOutputStream(Channels.newOutputStream(channel))) {
                out.writeInt(MAGIC);
                out.writeInt(version);
                out.writeByte(type);
                out.writeInt(payload.length);
                out.write(payload);
                out.write(sha256(payload));
                out.flush();
                channel.force(true);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /** Returns null only when the file is absent. */
    private static EvidenceRecord readRecord(File evidenceFile, int expectedType) throws IOException {
        Objects.requireNonNull(evidenceFile, "evidenceFile");
        Path path = evidenceFile.toPath();
        if (!Files.exists(path)) return null;
        if (!Files.isRegularFile(path)) {
            throw new EvidenceFormatException("Build evidence is not a regular file: " + evidenceFile);
        }
        long fileSize = Files.size(path);
        long maximumSize = (long) HEADER_BYTES + MAX_PAYLOAD_BYTES + CHECKSUM_BYTES;
        if (fileSize < HEADER_BYTES + CHECKSUM_BYTES || fileSize > maximumSize) {
            throw new EvidenceFormatException("Invalid build evidence file size: " + fileSize);
        }

        try (DataInputStream in = new DataInputStream(Files.newInputStream(path))) {
            int magic = in.readInt();
            if (magic != MAGIC) throw new EvidenceFormatException("Invalid build evidence magic");
            int version = in.readInt();
            if (version < 1 || version > FORMAT_VERSION) {
                throw new EvidenceFormatException("Unsupported build evidence version " + version
                        + " (supported 1.." + FORMAT_VERSION + ")");
            }
            int actualType = in.readUnsignedByte();
            if (actualType != TYPE_CFG && actualType != TYPE_STRING
                    && actualType != TYPE_CFG_PENDING) {
                throw new EvidenceFormatException("Unknown build evidence kind " + actualType);
            }
            if (actualType != expectedType) {
                throw new EvidenceFormatException("Wrong build evidence kind " + actualType
                        + " (expected " + expectedType + ")");
            }
            int payloadLength = in.readInt();
            if (payloadLength < 0 || payloadLength > MAX_PAYLOAD_BYTES) {
                throw new EvidenceFormatException("Invalid build evidence payload length "
                        + payloadLength);
            }
            long expectedSize = (long) HEADER_BYTES + payloadLength + CHECKSUM_BYTES;
            if (fileSize != expectedSize) {
                throw new EvidenceFormatException("Build evidence length mismatch: header declares "
                        + expectedSize + " bytes, file has " + fileSize);
            }
            byte[] payload = new byte[payloadLength];
            in.readFully(payload);
            byte[] checksum = new byte[CHECKSUM_BYTES];
            in.readFully(checksum);
            if (in.read() != -1) throw new EvidenceFormatException("Trailing build evidence bytes");
            if (!MessageDigest.isEqual(checksum, sha256(payload))) {
                throw new EvidenceFormatException("Build evidence checksum mismatch");
            }
            return new EvidenceRecord(version, payload);
        } catch (EvidenceFormatException e) {
            throw e;
        } catch (EOFException e) {
            throw new EvidenceFormatException("Truncated build evidence record", e);
        }
    }

    private static void writeStats(DataOutputStream out, ObfuscatorStats stats) throws IOException {
        writeStats(out, stats, FORMAT_VERSION);
    }

    private static void writeStats(DataOutputStream out, ObfuscatorStats stats, int formatVersion)
            throws IOException {
        writeCount(out, stats.dexProcessed, "dexProcessed");
        writeCount(out, stats.dexVerified, "dexVerified");
        writeCount(out, stats.dexFailed, "dexFailed");
        writeCount(out, stats.classesScanned, "classesScanned");
        writeCount(out, stats.methodsScanned, "methodsScanned");
        writeCount(out, stats.methodsObfuscated, "methodsObfuscated");
        writeCount(out, stats.methodsFlattened, "methodsFlattened");
        writeCount(out, stats.methodsReordered, "methodsReordered");
        writeCount(out, stats.reorderedTryCatch, "reorderedTryCatch");
        writeCount(out, stats.reorderedRegConflict, "reorderedRegConflict");
        writeCount(out, stats.reorderedVerifierRisk, "reorderedVerifierRisk");
        writeCount(out, stats.methodsSkippedNotIncluded, "methodsSkippedNotIncluded");
        writeCount(out, stats.methodsSkippedTryCatch, "methodsSkippedTryCatch");
        writeCount(out, stats.methodsSkippedTooSmall, "methodsSkippedTooSmall");
        writeCount(out, stats.methodsSkippedTooLarge, "methodsSkippedTooLarge");
        writeCount(out, stats.methodsSkippedUnsupported, "methodsSkippedUnsupported");
        writeCount(out, stats.methodsSkippedAlreadyObfuscated, "methodsSkippedAlreadyObfuscated");
        writeCount(out, stats.methodsSkippedVerifierAnalysis, "methodsSkippedVerifierAnalysis");
        writeCount(out, stats.methodsSkippedRegisterBudget, "methodsSkippedRegisterBudget");
        writeCount(out, stats.switchesPadded, "switchesPadded");
        writeCount(out, stats.switchCasesBefore, "switchCasesBefore");
        writeCount(out, stats.switchCasesAfter, "switchCasesAfter");
        writeCount(out, stats.fakeSwitchCases, "fakeSwitchCases");
        writeCount(out, stats.symbolSwitchCases, "symbolSwitchCases");
        writeCount(out, stats.regionalDispatchers, "regionalDispatchers");
        writeCount(out, stats.reachableAliasCases, "reachableAliasCases");
        writeCount(out, stats.stateSharedMethods, "stateSharedMethods");
        out.writeBoolean(stats.stringEncryptionEnabled);
        writeString(out, stats.stringEncryptionMode, "stringEncryptionMode");
        writeString(out, stats.stringCoverageStatus, "stringCoverageStatus");
        writeCount(out, stats.stringClassesVisited, "stringClassesVisited");
        writeCount(out, stats.stringClassesModified, "stringClassesModified");
        writeCount(out, stats.stringConstantsEncrypted, "stringConstantsEncrypted");
        writeCount(out, stats.stringConstantsSkipped, "stringConstantsSkipped");
        if (formatVersion >= 4) {
            writeCount(out, stats.stringSkippedWhitespace, "stringSkippedWhitespace");
            writeCount(out, stats.stringSkippedTooLarge, "stringSkippedTooLarge");
            writeCount(out, stats.stringSkippedInvalidUnicode, "stringSkippedInvalidUnicode");
            writeCount(out, stats.stringSkippedFiltered, "stringSkippedFiltered");
        }
        writeCount(out, stats.stringUnsupportedConstants, "stringUnsupportedConstants");
        writeCount(out, stats.stringIdentityCiphertexts, "stringIdentityCiphertexts");
        out.writeBoolean(stats.stringPlaintextVerified);
        writeCount(out, stats.stringDexFilesScanned, "stringDexFilesScanned");
        writeCount(out, stats.stringPoolEntriesScanned, "stringPoolEntriesScanned");
        writeCount(out, stats.stringPlaintextHashesTracked, "stringPlaintextHashesTracked");
        writeString(out, stats.stringPlaintextGateMode, "stringPlaintextGateMode");
        writeCount(out, stats.stringPlaintextLeaks, "stringPlaintextLeaks");
        writeCount(out, stats.stringPlaintextLeakOccurrences, "stringPlaintextLeakOccurrences");
        writeCount(out, stats.stringRuntimePlaintextLeaks, "stringRuntimePlaintextLeaks");
        writeCount(out, stats.stringRuntimePlaintextLeakOccurrences,
                "stringRuntimePlaintextLeakOccurrences");
        writeCount(out, stats.stringWholePoolPlaintextCollisions,
                "stringWholePoolPlaintextCollisions");
        writeCount(out, stats.stringWholePoolPlaintextCollisionOccurrences,
                "stringWholePoolPlaintextCollisionOccurrences");
        writeCount(out, stats.stringConstStringReferencesScanned,
                "stringConstStringReferencesScanned");
        writeCount(out, stats.stringStaticStringValuesScanned,
                "stringStaticStringValuesScanned");
        writeCount(out, stats.stringAnnotationStringValuesScanned,
                "stringAnnotationStringValuesScanned");
        writeCount(out, stats.stringCallSiteStringValuesScanned,
                "stringCallSiteStringValuesScanned");
        if (formatVersion >= 3) {
            writeCount(out, stats.cfgResolvedClassWideOwners,
                    "cfgResolvedClassWideOwners");
            writeCount(out, stats.cfgResolvedMemberOnlyOwners,
                    "cfgResolvedMemberOnlyOwners");
            writeCount(out, stats.cfgResolvedMemberMethods,
                    "cfgResolvedMemberMethods");
            writeCount(out, stats.cfgRequiredMethodsResolved,
                    "cfgRequiredMethodsResolved");
            writeCount(out, stats.cfgRequiredMethodsScanned,
                    "cfgRequiredMethodsScanned");
            writeCount(out, stats.cfgRequiredMethodsObfuscated,
                    "cfgRequiredMethodsObfuscated");
            writeCount(out, stats.stringScopedRuntimePlaintextLeaks,
                    "stringScopedRuntimePlaintextLeaks");
            writeCount(out, stats.stringScopedRuntimePlaintextLeakOccurrences,
                    "stringScopedRuntimePlaintextLeakOccurrences");
            if (formatVersion >= 5) {
                writeCount(out, stats.stringGlobalRuntimeFallbackHashesTracked,
                        "stringGlobalRuntimeFallbackHashesTracked");
                writeCount(out, stats.stringGlobalRuntimeFallbackPlaintextLeaks,
                        "stringGlobalRuntimeFallbackPlaintextLeaks");
                writeCount(out, stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences,
                        "stringGlobalRuntimeFallbackPlaintextLeakOccurrences");
            }
            writeCount(out, stats.stringOwnerRuntimePlaintextCollisions,
                    "stringOwnerRuntimePlaintextCollisions");
            writeCount(out, stats.stringOwnerRuntimePlaintextCollisionOccurrences,
                    "stringOwnerRuntimePlaintextCollisionOccurrences");
            writeCount(out, stats.stringGlobalRuntimePlaintextCollisions,
                    "stringGlobalRuntimePlaintextCollisions");
            writeCount(out, stats.stringGlobalRuntimePlaintextCollisionOccurrences,
                    "stringGlobalRuntimePlaintextCollisionOccurrences");
            writeCount(out, stats.stringTargetClassesResolved, "stringTargetClassesResolved");
            writeCount(out, stats.stringTargetClassesScanned, "stringTargetClassesScanned");
            writeCount(out, stats.stringTargetMethodsResolved, "stringTargetMethodsResolved");
            writeCount(out, stats.stringTargetMethodsScanned, "stringTargetMethodsScanned");
            writeCount(out, stats.stringTargetFieldsResolved, "stringTargetFieldsResolved");
            writeCount(out, stats.stringTargetFieldsScanned, "stringTargetFieldsScanned");
            if (formatVersion >= 6) {
                writeCount(out, stats.stringR8MappedMethodSites,
                        "stringR8MappedMethodSites");
                writeCount(out, stats.stringR8RemovedMethodSites,
                        "stringR8RemovedMethodSites");
                writeCount(out, stats.stringR8IdentityMethodSites,
                        "stringR8IdentityMethodSites");
                writeCount(out, stats.stringR8FallbackMethodSites,
                        "stringR8FallbackMethodSites");
                writeCount(out, stats.stringR8MappedFieldProvenance,
                        "stringR8MappedFieldProvenance");
                writeCount(out, stats.stringR8RemovedFieldProvenance,
                        "stringR8RemovedFieldProvenance");
                writeCount(out, stats.stringR8IdentityFieldProvenance,
                        "stringR8IdentityFieldProvenance");
                writeCount(out, stats.stringR8FallbackFieldProvenance,
                        "stringR8FallbackFieldProvenance");
                writeCount(out, stats.stringRemovedOriginalSiteHashesTracked,
                        "stringRemovedOriginalSiteHashesTracked");
                writeCount(out, stats.stringIdentityFieldProvenanceResolved,
                        "stringIdentityFieldProvenanceResolved");
                writeCount(out, stats.stringIdentityFieldProvenanceScanned,
                        "stringIdentityFieldProvenanceScanned");
            }
            writeCount(out, stats.stringStructuralAnnotationStringValuesScanned,
                    "stringStructuralAnnotationStringValuesScanned");
            writeCount(out, stats.stringStructuralAnnotationPlaintextCollisions,
                    "stringStructuralAnnotationPlaintextCollisions");
            writeCount(out, stats.stringStructuralAnnotationPlaintextCollisionOccurrences,
                    "stringStructuralAnnotationPlaintextCollisionOccurrences");
        }
        writeCount(out, stats.stringMinEncryptedStrings, "stringMinEncryptedStrings");
        writeCount(out, stats.stringMinModifiedClasses, "stringMinModifiedClasses");
        writeCount(out, stats.stringMaxSkippedStrings, "stringMaxSkippedStrings");
        if (formatVersion >= 4) {
            writeCount(out, stats.stringMaxUnsafeSkippedStrings,
                    "stringMaxUnsafeSkippedStrings");
            writeCount(out, stats.stringMaxFilteredStrings, "stringMaxFilteredStrings");
        }
        out.writeBoolean(stats.stringFailOnUnknownCoverage);
        out.writeBoolean(stats.stringVerifyFinalDex);
        out.writeBoolean(stats.stringFailOnPlaintextLeak);
        out.writeBoolean(stats.stringFailOnUnsupportedConstants);
        out.writeBoolean(stats.stringFailOnUnprotectedDecryptor);
        writeString(out, stats.artifactFingerprint, "artifactFingerprint");
        writeString(out, stats.cfgTransformDigest, "cfgTransformDigest");
        writeString(out, stats.stringTransformDigest, "stringTransformDigest");
        writeString(out, stats.evidenceSource, "evidenceSource");
        writeNonNegativeLong(out, stats.originalDexBytes, "originalDexBytes");
        writeNonNegativeLong(out, stats.outputDexBytes, "outputDexBytes");

        if (stats.methodReports.size() > MAX_METHOD_REPORTS) {
            throw new IllegalArgumentException("Too many method reports: "
                    + stats.methodReports.size());
        }
        out.writeInt(stats.methodReports.size());
        for (MethodReport report : stats.methodReports) writeMethodReport(out, report);
    }

    private static ObfuscatorStats readStats(DataInputStream in, int formatVersion)
            throws IOException {
        ObfuscatorStats stats = new ObfuscatorStats();
        stats.dexProcessed = readCount(in, "dexProcessed");
        stats.dexVerified = readCount(in, "dexVerified");
        stats.dexFailed = readCount(in, "dexFailed");
        stats.classesScanned = readCount(in, "classesScanned");
        stats.methodsScanned = readCount(in, "methodsScanned");
        stats.methodsObfuscated = readCount(in, "methodsObfuscated");
        stats.methodsFlattened = readCount(in, "methodsFlattened");
        stats.methodsReordered = readCount(in, "methodsReordered");
        stats.reorderedTryCatch = readCount(in, "reorderedTryCatch");
        stats.reorderedRegConflict = readCount(in, "reorderedRegConflict");
        stats.reorderedVerifierRisk = readCount(in, "reorderedVerifierRisk");
        stats.methodsSkippedNotIncluded = readCount(in, "methodsSkippedNotIncluded");
        stats.methodsSkippedTryCatch = readCount(in, "methodsSkippedTryCatch");
        stats.methodsSkippedTooSmall = readCount(in, "methodsSkippedTooSmall");
        stats.methodsSkippedTooLarge = readCount(in, "methodsSkippedTooLarge");
        stats.methodsSkippedUnsupported = readCount(in, "methodsSkippedUnsupported");
        stats.methodsSkippedAlreadyObfuscated = readCount(in, "methodsSkippedAlreadyObfuscated");
        stats.methodsSkippedVerifierAnalysis = readCount(in, "methodsSkippedVerifierAnalysis");
        stats.methodsSkippedRegisterBudget = readCount(in, "methodsSkippedRegisterBudget");
        stats.switchesPadded = readCount(in, "switchesPadded");
        stats.switchCasesBefore = readCount(in, "switchCasesBefore");
        stats.switchCasesAfter = readCount(in, "switchCasesAfter");
        stats.fakeSwitchCases = readCount(in, "fakeSwitchCases");
        stats.symbolSwitchCases = readCount(in, "symbolSwitchCases");
        stats.regionalDispatchers = readCount(in, "regionalDispatchers");
        stats.reachableAliasCases = readCount(in, "reachableAliasCases");
        stats.stateSharedMethods = readCount(in, "stateSharedMethods");
        stats.stringEncryptionEnabled = readBoolean(in, "stringEncryptionEnabled");
        stats.stringEncryptionMode = readRequiredString(in, "stringEncryptionMode");
        stats.stringCoverageStatus = readRequiredString(in, "stringCoverageStatus");
        stats.stringClassesVisited = readCount(in, "stringClassesVisited");
        stats.stringClassesModified = readCount(in, "stringClassesModified");
        stats.stringConstantsEncrypted = readCount(in, "stringConstantsEncrypted");
        stats.stringConstantsSkipped = readCount(in, "stringConstantsSkipped");
        if (formatVersion >= 4) {
            stats.stringSkippedWhitespace = readCount(in, "stringSkippedWhitespace");
            stats.stringSkippedTooLarge = readCount(in, "stringSkippedTooLarge");
            stats.stringSkippedInvalidUnicode = readCount(in, "stringSkippedInvalidUnicode");
            stats.stringSkippedFiltered = readCount(in, "stringSkippedFiltered");
        }
        stats.stringUnsupportedConstants = readCount(in, "stringUnsupportedConstants");
        stats.stringIdentityCiphertexts = readCount(in, "stringIdentityCiphertexts");
        stats.stringPlaintextVerified = readBoolean(in, "stringPlaintextVerified");
        stats.stringDexFilesScanned = readCount(in, "stringDexFilesScanned");
        stats.stringPoolEntriesScanned = readCount(in, "stringPoolEntriesScanned");
        stats.stringPlaintextHashesTracked = readCount(in, "stringPlaintextHashesTracked");
        if (formatVersion >= 2) {
            stats.stringPlaintextGateMode = readRequiredString(in, "stringPlaintextGateMode");
            stats.stringPlaintextLeaks = readCount(in, "stringPlaintextLeaks");
            stats.stringPlaintextLeakOccurrences = readCount(in,
                    "stringPlaintextLeakOccurrences");
            stats.stringRuntimePlaintextLeaks = readCount(in, "stringRuntimePlaintextLeaks");
            stats.stringRuntimePlaintextLeakOccurrences = readCount(in,
                    "stringRuntimePlaintextLeakOccurrences");
            stats.stringWholePoolPlaintextCollisions = readCount(in,
                    "stringWholePoolPlaintextCollisions");
            stats.stringWholePoolPlaintextCollisionOccurrences = readCount(in,
                    "stringWholePoolPlaintextCollisionOccurrences");
            stats.stringConstStringReferencesScanned = readCount(in,
                    "stringConstStringReferencesScanned");
            stats.stringStaticStringValuesScanned = readCount(in,
                    "stringStaticStringValuesScanned");
            stats.stringAnnotationStringValuesScanned = readCount(in,
                    "stringAnnotationStringValuesScanned");
            stats.stringCallSiteStringValuesScanned = readCount(in,
                    "stringCallSiteStringValuesScanned");
            if (formatVersion >= 3) {
                stats.cfgResolvedClassWideOwners = readCount(in,
                        "cfgResolvedClassWideOwners");
                stats.cfgResolvedMemberOnlyOwners = readCount(in,
                        "cfgResolvedMemberOnlyOwners");
                stats.cfgResolvedMemberMethods = readCount(in,
                        "cfgResolvedMemberMethods");
                stats.cfgRequiredMethodsResolved = readCount(in,
                        "cfgRequiredMethodsResolved");
                stats.cfgRequiredMethodsScanned = readCount(in,
                        "cfgRequiredMethodsScanned");
                stats.cfgRequiredMethodsObfuscated = readCount(in,
                        "cfgRequiredMethodsObfuscated");
                stats.stringScopedRuntimePlaintextLeaks = readCount(in,
                        "stringScopedRuntimePlaintextLeaks");
                stats.stringScopedRuntimePlaintextLeakOccurrences = readCount(in,
                        "stringScopedRuntimePlaintextLeakOccurrences");
                if (formatVersion >= 5) {
                    stats.stringGlobalRuntimeFallbackHashesTracked = readCount(in,
                            "stringGlobalRuntimeFallbackHashesTracked");
                    stats.stringGlobalRuntimeFallbackPlaintextLeaks = readCount(in,
                            "stringGlobalRuntimeFallbackPlaintextLeaks");
                    stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = readCount(in,
                            "stringGlobalRuntimeFallbackPlaintextLeakOccurrences");
                }
                stats.stringOwnerRuntimePlaintextCollisions = readCount(in,
                        "stringOwnerRuntimePlaintextCollisions");
                stats.stringOwnerRuntimePlaintextCollisionOccurrences = readCount(in,
                        "stringOwnerRuntimePlaintextCollisionOccurrences");
                stats.stringGlobalRuntimePlaintextCollisions = readCount(in,
                        "stringGlobalRuntimePlaintextCollisions");
                stats.stringGlobalRuntimePlaintextCollisionOccurrences = readCount(in,
                        "stringGlobalRuntimePlaintextCollisionOccurrences");
                stats.stringTargetClassesResolved = readCount(in,
                        "stringTargetClassesResolved");
                stats.stringTargetClassesScanned = readCount(in,
                        "stringTargetClassesScanned");
                stats.stringTargetMethodsResolved = readCount(in,
                        "stringTargetMethodsResolved");
                stats.stringTargetMethodsScanned = readCount(in,
                        "stringTargetMethodsScanned");
                stats.stringTargetFieldsResolved = readCount(in,
                        "stringTargetFieldsResolved");
                stats.stringTargetFieldsScanned = readCount(in,
                        "stringTargetFieldsScanned");
                if (formatVersion >= 6) {
                    stats.stringR8MappedMethodSites = readCount(in,
                            "stringR8MappedMethodSites");
                    stats.stringR8RemovedMethodSites = readCount(in,
                            "stringR8RemovedMethodSites");
                    stats.stringR8IdentityMethodSites = readCount(in,
                            "stringR8IdentityMethodSites");
                    stats.stringR8FallbackMethodSites = readCount(in,
                            "stringR8FallbackMethodSites");
                    stats.stringR8MappedFieldProvenance = readCount(in,
                            "stringR8MappedFieldProvenance");
                    stats.stringR8RemovedFieldProvenance = readCount(in,
                            "stringR8RemovedFieldProvenance");
                    stats.stringR8IdentityFieldProvenance = readCount(in,
                            "stringR8IdentityFieldProvenance");
                    stats.stringR8FallbackFieldProvenance = readCount(in,
                            "stringR8FallbackFieldProvenance");
                    stats.stringRemovedOriginalSiteHashesTracked = readCount(in,
                            "stringRemovedOriginalSiteHashesTracked");
                    stats.stringIdentityFieldProvenanceResolved = readCount(in,
                            "stringIdentityFieldProvenanceResolved");
                    stats.stringIdentityFieldProvenanceScanned = readCount(in,
                            "stringIdentityFieldProvenanceScanned");
                }
                stats.stringStructuralAnnotationStringValuesScanned = readCount(in,
                        "stringStructuralAnnotationStringValuesScanned");
                stats.stringStructuralAnnotationPlaintextCollisions = readCount(in,
                        "stringStructuralAnnotationPlaintextCollisions");
                stats.stringStructuralAnnotationPlaintextCollisionOccurrences = readCount(in,
                        "stringStructuralAnnotationPlaintextCollisionOccurrences");
            } else {
                // v2 had one unscoped runtime count. It is diagnostic only when restored; the
                // missing owner scope prevents an application gate from trusting this record.
                stats.stringGlobalRuntimePlaintextCollisions =
                        stats.stringRuntimePlaintextLeaks;
                stats.stringGlobalRuntimePlaintextCollisionOccurrences =
                        stats.stringRuntimePlaintextLeakOccurrences;
            }
        } else {
            // Version 1 used whole-pool matches as the only gate result.
            stats.stringPlaintextLeaks = readCount(in, "stringPlaintextLeaks");
            stats.stringPlaintextLeakOccurrences = readCount(in,
                    "stringPlaintextLeakOccurrences");
            stats.stringPlaintextGateMode = stats.stringPlaintextVerified
                    ? "STRICT_WHOLE_POOL" : "DISABLED";
            stats.stringWholePoolPlaintextCollisions = stats.stringPlaintextLeaks;
            stats.stringWholePoolPlaintextCollisionOccurrences =
                    stats.stringPlaintextLeakOccurrences;
        }
        stats.stringMinEncryptedStrings = readCount(in, "stringMinEncryptedStrings");
        stats.stringMinModifiedClasses = readCount(in, "stringMinModifiedClasses");
        stats.stringMaxSkippedStrings = readCount(in, "stringMaxSkippedStrings");
        if (formatVersion >= 4) {
            stats.stringMaxUnsafeSkippedStrings = readCount(in,
                    "stringMaxUnsafeSkippedStrings");
            stats.stringMaxFilteredStrings = readCount(in, "stringMaxFilteredStrings");
        }
        stats.stringFailOnUnknownCoverage = readBoolean(in, "stringFailOnUnknownCoverage");
        stats.stringVerifyFinalDex = readBoolean(in, "stringVerifyFinalDex");
        stats.stringFailOnPlaintextLeak = readBoolean(in, "stringFailOnPlaintextLeak");
        stats.stringFailOnUnsupportedConstants = readBoolean(in, "stringFailOnUnsupportedConstants");
        stats.stringFailOnUnprotectedDecryptor = readBoolean(in,
                "stringFailOnUnprotectedDecryptor");
        stats.artifactFingerprint = readOptionalString(in, "artifactFingerprint");
        stats.cfgTransformDigest = readOptionalString(in, "cfgTransformDigest");
        stats.stringTransformDigest = readOptionalString(in, "stringTransformDigest");
        stats.evidenceSource = readOptionalString(in, "evidenceSource");
        stats.originalDexBytes = readNonNegativeLong(in, "originalDexBytes");
        stats.outputDexBytes = readNonNegativeLong(in, "outputDexBytes");

        int reportCount = readBoundedCount(in, "method report count", MAX_METHOD_REPORTS);
        for (int i = 0; i < reportCount; i++) stats.methodReports.add(readMethodReport(in));
        return stats;
    }

    private static final class EvidenceRecord {
        final int version;
        final byte[] payload;

        EvidenceRecord(int version, byte[] payload) {
            this.version = version;
            this.payload = payload;
        }
    }

    private static void writeMethodReport(DataOutputStream out, MethodReport report)
            throws IOException {
        if (report == null) throw new IllegalArgumentException("methodReports contains null");
        writeString(out, report.dex, "methodReport.dex");
        writeString(out, report.owner, "methodReport.owner");
        writeString(out, report.name, "methodReport.name");
        writeString(out, report.descriptor, "methodReport.descriptor");
        writeString(out, report.mode, "methodReport.mode");
        writeString(out, report.reason, "methodReport.reason");
        writeString(out, report.template, "methodReport.template");
        writeCount(out, report.instructionsBefore, "methodReport.instructionsBefore");
        writeCount(out, report.instructionsAfter, "methodReport.instructionsAfter");
        writeCount(out, report.codeUnitsBefore, "methodReport.codeUnitsBefore");
        writeCount(out, report.codeUnitsAfter, "methodReport.codeUnitsAfter");
        writeCount(out, report.registersBefore, "methodReport.registersBefore");
        writeCount(out, report.registersAfter, "methodReport.registersAfter");
        out.writeBoolean(report.hasTry);
        out.writeBoolean(report.hasSwitch);
        out.writeBoolean(report.hasArrayPayload);
        out.writeBoolean(report.registerTypesSeparated);
        writeCount(out, report.addedRegisters, "methodReport.addedRegisters");
        writeCount(out, report.switchesPadded, "methodReport.switchesPadded");
        writeCount(out, report.switchCasesBefore, "methodReport.switchCasesBefore");
        writeCount(out, report.switchCasesAfter, "methodReport.switchCasesAfter");
        writeCount(out, report.fakeSwitchCases, "methodReport.fakeSwitchCases");
        writeCount(out, report.symbolSwitchCases, "methodReport.symbolSwitchCases");
        writeCount(out, report.dispatcherRegions, "methodReport.dispatcherRegions");
        writeCount(out, report.reachableAliasCases, "methodReport.reachableAliasCases");
        writeCount(out, report.stateShareRegisters, "methodReport.stateShareRegisters");
    }

    private static MethodReport readMethodReport(DataInputStream in) throws IOException {
        String dex = readRequiredString(in, "methodReport.dex");
        String owner = readRequiredString(in, "methodReport.owner");
        String name = readRequiredString(in, "methodReport.name");
        String descriptor = readRequiredString(in, "methodReport.descriptor");
        String mode = readRequiredString(in, "methodReport.mode");
        String reason = readRequiredString(in, "methodReport.reason");
        String template = readRequiredString(in, "methodReport.template");
        int instructionsBefore = readCount(in, "methodReport.instructionsBefore");
        int instructionsAfter = readCount(in, "methodReport.instructionsAfter");
        int codeUnitsBefore = readCount(in, "methodReport.codeUnitsBefore");
        int codeUnitsAfter = readCount(in, "methodReport.codeUnitsAfter");
        int registersBefore = readCount(in, "methodReport.registersBefore");
        int registersAfter = readCount(in, "methodReport.registersAfter");
        boolean hasTry = readBoolean(in, "methodReport.hasTry");
        boolean hasSwitch = readBoolean(in, "methodReport.hasSwitch");
        boolean hasArrayPayload = readBoolean(in, "methodReport.hasArrayPayload");
        boolean registerTypesSeparated = readBoolean(in, "methodReport.registerTypesSeparated");
        int addedRegisters = readCount(in, "methodReport.addedRegisters");
        int switchesPadded = readCount(in, "methodReport.switchesPadded");
        int switchCasesBefore = readCount(in, "methodReport.switchCasesBefore");
        int switchCasesAfter = readCount(in, "methodReport.switchCasesAfter");
        int fakeSwitchCases = readCount(in, "methodReport.fakeSwitchCases");
        int symbolSwitchCases = readCount(in, "methodReport.symbolSwitchCases");
        int dispatcherRegions = readCount(in, "methodReport.dispatcherRegions");
        int reachableAliasCases = readCount(in, "methodReport.reachableAliasCases");
        int stateShareRegisters = readCount(in, "methodReport.stateShareRegisters");
        return MethodReport.restore(dex, owner, name, descriptor, mode, reason, template,
                instructionsBefore, instructionsAfter, codeUnitsBefore, codeUnitsAfter,
                registersBefore, registersAfter, hasTry, hasSwitch, hasArrayPayload,
                registerTypesSeparated, addedRegisters, switchesPadded, switchCasesBefore,
                switchCasesAfter, fakeSwitchCases, symbolSwitchCases, dispatcherRegions,
                reachableAliasCases, stateShareRegisters);
    }

    private static ObfuscatorStats copyStats(ObfuscatorStats source) {
        ObfuscatorStats copy = new ObfuscatorStats();
        copy.dexProcessed = source.dexProcessed;
        copy.dexVerified = source.dexVerified;
        copy.dexFailed = source.dexFailed;
        copy.classesScanned = source.classesScanned;
        copy.methodsScanned = source.methodsScanned;
        copy.methodsObfuscated = source.methodsObfuscated;
        copy.methodsFlattened = source.methodsFlattened;
        copy.methodsReordered = source.methodsReordered;
        copy.reorderedTryCatch = source.reorderedTryCatch;
        copy.reorderedRegConflict = source.reorderedRegConflict;
        copy.reorderedVerifierRisk = source.reorderedVerifierRisk;
        copy.methodsSkippedNotIncluded = source.methodsSkippedNotIncluded;
        copy.methodsSkippedTryCatch = source.methodsSkippedTryCatch;
        copy.methodsSkippedTooSmall = source.methodsSkippedTooSmall;
        copy.methodsSkippedTooLarge = source.methodsSkippedTooLarge;
        copy.methodsSkippedUnsupported = source.methodsSkippedUnsupported;
        copy.methodsSkippedAlreadyObfuscated = source.methodsSkippedAlreadyObfuscated;
        copy.methodsSkippedVerifierAnalysis = source.methodsSkippedVerifierAnalysis;
        copy.methodsSkippedRegisterBudget = source.methodsSkippedRegisterBudget;
        copy.cfgResolvedClassWideOwners = source.cfgResolvedClassWideOwners;
        copy.cfgResolvedMemberOnlyOwners = source.cfgResolvedMemberOnlyOwners;
        copy.cfgResolvedMemberMethods = source.cfgResolvedMemberMethods;
        copy.cfgRequiredMethodsResolved = source.cfgRequiredMethodsResolved;
        copy.cfgRequiredMethodsScanned = source.cfgRequiredMethodsScanned;
        copy.cfgRequiredMethodsObfuscated = source.cfgRequiredMethodsObfuscated;
        copy.switchesPadded = source.switchesPadded;
        copy.switchCasesBefore = source.switchCasesBefore;
        copy.switchCasesAfter = source.switchCasesAfter;
        copy.fakeSwitchCases = source.fakeSwitchCases;
        copy.symbolSwitchCases = source.symbolSwitchCases;
        copy.regionalDispatchers = source.regionalDispatchers;
        copy.reachableAliasCases = source.reachableAliasCases;
        copy.stateSharedMethods = source.stateSharedMethods;
        copy.stringEncryptionEnabled = source.stringEncryptionEnabled;
        copy.stringEncryptionMode = source.stringEncryptionMode;
        copy.stringCoverageStatus = source.stringCoverageStatus;
        copy.stringClassesVisited = source.stringClassesVisited;
        copy.stringClassesModified = source.stringClassesModified;
        copy.stringConstantsEncrypted = source.stringConstantsEncrypted;
        copy.stringConstantsSkipped = source.stringConstantsSkipped;
        copy.stringSkippedWhitespace = source.stringSkippedWhitespace;
        copy.stringSkippedTooLarge = source.stringSkippedTooLarge;
        copy.stringSkippedInvalidUnicode = source.stringSkippedInvalidUnicode;
        copy.stringSkippedFiltered = source.stringSkippedFiltered;
        copy.stringUnsupportedConstants = source.stringUnsupportedConstants;
        copy.stringIdentityCiphertexts = source.stringIdentityCiphertexts;
        copy.stringPlaintextVerified = source.stringPlaintextVerified;
        copy.stringDexFilesScanned = source.stringDexFilesScanned;
        copy.stringPoolEntriesScanned = source.stringPoolEntriesScanned;
        copy.stringPlaintextHashesTracked = source.stringPlaintextHashesTracked;
        copy.stringPlaintextGateMode = source.stringPlaintextGateMode;
        copy.stringPlaintextLeaks = source.stringPlaintextLeaks;
        copy.stringPlaintextLeakOccurrences = source.stringPlaintextLeakOccurrences;
        copy.stringRuntimePlaintextLeaks = source.stringRuntimePlaintextLeaks;
        copy.stringRuntimePlaintextLeakOccurrences = source.stringRuntimePlaintextLeakOccurrences;
        copy.stringScopedRuntimePlaintextLeaks = source.stringScopedRuntimePlaintextLeaks;
        copy.stringScopedRuntimePlaintextLeakOccurrences =
                source.stringScopedRuntimePlaintextLeakOccurrences;
        copy.stringGlobalRuntimeFallbackHashesTracked =
                source.stringGlobalRuntimeFallbackHashesTracked;
        copy.stringGlobalRuntimeFallbackPlaintextLeaks =
                source.stringGlobalRuntimeFallbackPlaintextLeaks;
        copy.stringGlobalRuntimeFallbackPlaintextLeakOccurrences =
                source.stringGlobalRuntimeFallbackPlaintextLeakOccurrences;
        copy.stringOwnerRuntimePlaintextCollisions =
                source.stringOwnerRuntimePlaintextCollisions;
        copy.stringOwnerRuntimePlaintextCollisionOccurrences =
                source.stringOwnerRuntimePlaintextCollisionOccurrences;
        copy.stringGlobalRuntimePlaintextCollisions =
                source.stringGlobalRuntimePlaintextCollisions;
        copy.stringGlobalRuntimePlaintextCollisionOccurrences =
                source.stringGlobalRuntimePlaintextCollisionOccurrences;
        copy.stringWholePoolPlaintextCollisions = source.stringWholePoolPlaintextCollisions;
        copy.stringWholePoolPlaintextCollisionOccurrences =
                source.stringWholePoolPlaintextCollisionOccurrences;
        copy.stringTargetClassesResolved = source.stringTargetClassesResolved;
        copy.stringTargetClassesScanned = source.stringTargetClassesScanned;
        copy.stringTargetMethodsResolved = source.stringTargetMethodsResolved;
        copy.stringTargetMethodsScanned = source.stringTargetMethodsScanned;
        copy.stringTargetFieldsResolved = source.stringTargetFieldsResolved;
        copy.stringTargetFieldsScanned = source.stringTargetFieldsScanned;
        copy.stringR8MappedMethodSites = source.stringR8MappedMethodSites;
        copy.stringR8RemovedMethodSites = source.stringR8RemovedMethodSites;
        copy.stringR8IdentityMethodSites = source.stringR8IdentityMethodSites;
        copy.stringR8FallbackMethodSites = source.stringR8FallbackMethodSites;
        copy.stringR8MappedFieldProvenance = source.stringR8MappedFieldProvenance;
        copy.stringR8RemovedFieldProvenance = source.stringR8RemovedFieldProvenance;
        copy.stringR8IdentityFieldProvenance = source.stringR8IdentityFieldProvenance;
        copy.stringR8FallbackFieldProvenance = source.stringR8FallbackFieldProvenance;
        copy.stringRemovedOriginalSiteHashesTracked =
                source.stringRemovedOriginalSiteHashesTracked;
        copy.stringIdentityFieldProvenanceResolved =
                source.stringIdentityFieldProvenanceResolved;
        copy.stringIdentityFieldProvenanceScanned =
                source.stringIdentityFieldProvenanceScanned;
        copy.stringConstStringReferencesScanned = source.stringConstStringReferencesScanned;
        copy.stringStaticStringValuesScanned = source.stringStaticStringValuesScanned;
        copy.stringAnnotationStringValuesScanned = source.stringAnnotationStringValuesScanned;
        copy.stringCallSiteStringValuesScanned = source.stringCallSiteStringValuesScanned;
        copy.stringStructuralAnnotationStringValuesScanned =
                source.stringStructuralAnnotationStringValuesScanned;
        copy.stringStructuralAnnotationPlaintextCollisions =
                source.stringStructuralAnnotationPlaintextCollisions;
        copy.stringStructuralAnnotationPlaintextCollisionOccurrences =
                source.stringStructuralAnnotationPlaintextCollisionOccurrences;
        copy.stringMinEncryptedStrings = source.stringMinEncryptedStrings;
        copy.stringMinModifiedClasses = source.stringMinModifiedClasses;
        copy.stringMaxSkippedStrings = source.stringMaxSkippedStrings;
        copy.stringMaxUnsafeSkippedStrings = source.stringMaxUnsafeSkippedStrings;
        copy.stringMaxFilteredStrings = source.stringMaxFilteredStrings;
        copy.stringFailOnUnknownCoverage = source.stringFailOnUnknownCoverage;
        copy.stringVerifyFinalDex = source.stringVerifyFinalDex;
        copy.stringFailOnPlaintextLeak = source.stringFailOnPlaintextLeak;
        copy.stringFailOnUnsupportedConstants = source.stringFailOnUnsupportedConstants;
        copy.stringFailOnUnprotectedDecryptor = source.stringFailOnUnprotectedDecryptor;
        copy.artifactFingerprint = source.artifactFingerprint;
        copy.cfgTransformDigest = source.cfgTransformDigest;
        copy.stringTransformDigest = source.stringTransformDigest;
        copy.evidenceSource = source.evidenceSource;
        copy.originalDexBytes = source.originalDexBytes;
        copy.outputDexBytes = source.outputDexBytes;
        copy.methodReports.addAll(source.methodReports); // MethodReport is immutable.
        return copy;
    }

    private static Map<String, Set<String>> normalizeOwnerHashes(
            Map<String, ? extends Set<String>> ownerHashes, Set<String> allHashes) {
        Objects.requireNonNull(ownerHashes, "plaintextSha256ByOriginalClass");
        if (ownerHashes.size() > MAX_STRING_OWNER_CLASSES) {
            throw new IllegalArgumentException("Too many string original owners: "
                    + ownerHashes.size());
        }
        Map<String, Set<String>> normalized = new TreeMap<>();
        for (Map.Entry<String, ? extends Set<String>> entry : ownerHashes.entrySet()) {
            String owner = normalizeOriginalClassName(entry.getKey());
            if (owner.isEmpty()) {
                throw new IllegalArgumentException(
                        "plaintextSha256ByOriginalClass contains a blank owner");
            }
            Set<String> hashes = normalizePlaintextHashes(entry.getValue());
            if (hashes.isEmpty()) {
                throw new IllegalArgumentException("string original owner has no protected hashes");
            }
            if (!allHashes.containsAll(hashes)) {
                throw new IllegalArgumentException(
                        "owner plaintext hashes must be contained in plaintextSha256");
            }
            if (normalized.put(owner, hashes) != null) {
                throw new IllegalArgumentException(
                        "duplicate normalized string original owner");
            }
        }
        Set<String> scopedHashes = new TreeSet<>();
        for (Set<String> hashes : normalized.values()) scopedHashes.addAll(hashes);
        if (!scopedHashes.equals(allHashes)) {
            throw new IllegalArgumentException(
                    "plaintextSha256ByOriginalClass must cover every plaintextSha256 value");
        }
        return normalized;
    }

    private static Map<String, Set<String>> normalizeMemberHashes(
            Map<String, ? extends Set<String>> memberHashes, Set<String> allHashes,
            boolean method) {
        Objects.requireNonNull(memberHashes, method
                ? "plaintextSha256ByOriginalMethod" : "plaintextSha256ByOriginalField");
        if (memberHashes.size() > MAX_STRING_OWNER_CLASSES) {
            throw new IllegalArgumentException("Too many string original members: "
                    + memberHashes.size());
        }
        Map<String, Set<String>> normalized = new TreeMap<>();
        for (Map.Entry<String, ? extends Set<String>> entry : memberHashes.entrySet()) {
            String member = normalizeMemberKey(entry.getKey(), method);
            if (member.isEmpty()) {
                throw new IllegalArgumentException("invalid original string member scope");
            }
            Set<String> hashes = normalizePlaintextHashes(entry.getValue());
            if (hashes.isEmpty() || !allHashes.containsAll(hashes)) {
                throw new IllegalArgumentException(
                        "original string member scope contains invalid protected hashes");
            }
            if (normalized.put(member, hashes) != null) {
                throw new IllegalArgumentException("duplicate normalized string member scope");
            }
        }
        return normalized;
    }

    private static void writeNestedHashMap(DataOutputStream out,
                                           Map<String, Set<String>> values,
                                           String field) throws IOException {
        out.writeInt(values.size());
        for (Map.Entry<String, Set<String>> entry : values.entrySet()) {
            writeString(out, entry.getKey(), field);
            out.writeInt(entry.getValue().size());
            for (String hash : entry.getValue()) {
                writeString(out, hash, field + "PlaintextSha256");
            }
        }
    }

    private static Map<String, Set<String>> readNestedHashMap(
            DataInputStream in, Set<String> allHashes, String label, boolean method)
            throws IOException {
        int count = readBoundedCount(in, label + " count", MAX_STRING_OWNER_CLASSES);
        Map<String, Set<String>> values = new TreeMap<>();
        for (int i = 0; i < count; i++) {
            String rawMember = readRequiredString(in, label);
            String member = normalizeMemberKey(rawMember, method);
            if (member.isEmpty() || !member.equals(rawMember)) {
                throw new EvidenceFormatException("Non-canonical " + label + " at index " + i);
            }
            int hashCount = readBoundedCount(in, label + " plaintext SHA-256 count",
                    MAX_PLAINTEXT_HASHES);
            if (hashCount == 0) {
                throw new EvidenceFormatException(label + " has no protected hashes at index " + i);
            }
            Set<String> hashes = new TreeSet<>();
            for (int j = 0; j < hashCount; j++) {
                String hash = readRequiredString(in, label + "PlaintextSha256")
                        .toLowerCase(Locale.ROOT);
                if (!isSha256(hash) || !allHashes.contains(hash) || !hashes.add(hash)) {
                    throw new EvidenceFormatException("Invalid " + label
                            + " plaintext SHA-256 at index " + i + ":" + j);
                }
            }
            if (values.put(member, hashes) != null) {
                throw new EvidenceFormatException("Duplicate " + label + " at index " + i);
            }
        }
        return values;
    }

    private static String normalizeMemberKey(String value, boolean method) {
        if (value == null) return "";
        String trimmed = value.trim();
        int arrow = trimmed.indexOf("->");
        if (arrow <= 0 || trimmed.indexOf("->", arrow + 2) >= 0) return "";
        String owner = normalizeOriginalClassName(trimmed.substring(0, arrow));
        String member = trimmed.substring(arrow + 2);
        if (owner.isEmpty() || member.isEmpty() || member.indexOf('#') >= 0
                || member.indexOf(':') >= 0 || Character.isWhitespace(member.charAt(0))) {
            return "";
        }
        int open = member.indexOf('(');
        if (method) {
            if (open <= 0 || member.indexOf(')', open + 1) <= open) return "";
        } else if (open >= 0 || member.indexOf(')') >= 0) {
            return "";
        }
        return owner.replace('.', '/') + "->" + member;
    }

    private static Map<String, Set<String>> immutableNestedMap(
            Map<String, Set<String>> source) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> entry : new TreeMap<>(source).entrySet()) {
            result.put(entry.getKey(), Collections.unmodifiableSet(
                    new LinkedHashSet<>(new TreeSet<>(entry.getValue()))));
        }
        return Collections.unmodifiableMap(result);
    }

    private static String normalizeOriginalClassName(String value) {
        if (value == null) return "";
        String normalized = value.trim().replace('/', '.');
        if (normalized.startsWith("L") && normalized.endsWith(";")
                && normalized.length() > 2) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (normalized.isEmpty() || normalized.startsWith(".") || normalized.endsWith(".")
                || normalized.contains("..") || normalized.indexOf(';') >= 0
                || normalized.indexOf('[') >= 0) {
            return "";
        }
        return normalized;
    }

    private static Set<String> normalizePlaintextHashes(Set<String> hashes) {
        Objects.requireNonNull(hashes, "plaintextSha256");
        if (hashes.size() > MAX_PLAINTEXT_HASHES) {
            throw new IllegalArgumentException("Too many plaintext SHA-256 values: " + hashes.size());
        }
        Set<String> normalized = new TreeSet<>();
        for (String value : hashes) {
            if (value == null || !isSha256(value)) {
                throw new IllegalArgumentException("plaintextSha256 must contain only 64-digit hex SHA-256 values");
            }
            normalized.add(value.toLowerCase(Locale.ROOT));
        }
        return normalized;
    }

    private static boolean isSha256(String value) {
        if (value == null || value.length() != 64) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    }

    private static void writeString(DataOutputStream out, String value, String field)
            throws IOException {
        if (value == null) throw new IllegalArgumentException(field + " must not be null");
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > MAX_STRING_BYTES) {
            throw new IllegalArgumentException(field + " exceeds " + MAX_STRING_BYTES + " UTF-8 bytes");
        }
        out.writeInt(encoded.length);
        out.write(encoded);
    }

    private static String readRequiredString(DataInputStream in, String field) throws IOException {
        String decoded = readOptionalString(in, field);
        if (decoded.trim().isEmpty()) {
            throw new EvidenceFormatException(field + " must not be blank");
        }
        return decoded;
    }

    private static String readOptionalString(DataInputStream in, String field) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_STRING_BYTES) {
            throw new EvidenceFormatException("Invalid " + field + " length " + length);
        }
        byte[] encoded = new byte[length];
        in.readFully(encoded);
        final String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString();
        } catch (CharacterCodingException e) {
            throw new EvidenceFormatException("Invalid UTF-8 in " + field, e);
        }
        return decoded;
    }

    private static void writeCount(DataOutputStream out, int value, String field)
            throws IOException {
        if (value < 0) throw new IllegalArgumentException(field + " must be non-negative");
        out.writeInt(value);
    }

    private static int readCount(DataInputStream in, String field) throws IOException {
        int value = in.readInt();
        if (value < 0) throw new EvidenceFormatException(field + " must be non-negative");
        return value;
    }

    private static int readBoundedCount(DataInputStream in, String field, int maximum)
            throws IOException {
        int value = readCount(in, field);
        if (value > maximum) {
            throw new EvidenceFormatException(field + " exceeds " + maximum + ": " + value);
        }
        return value;
    }

    private static void writeNonNegativeLong(DataOutputStream out, long value, String field)
            throws IOException {
        if (value < 0L) throw new IllegalArgumentException(field + " must be non-negative");
        out.writeLong(value);
    }

    private static long readNonNegativeLong(DataInputStream in, String field) throws IOException {
        long value = in.readLong();
        if (value < 0L) throw new EvidenceFormatException(field + " must be non-negative");
        return value;
    }

    private static boolean readBoolean(DataInputStream in, String field) throws IOException {
        int value = in.readUnsignedByte();
        if (value == 0) return false;
        if (value == 1) return true;
        throw new EvidenceFormatException("Invalid boolean for " + field + ": " + value);
    }

    private static void requirePayloadExhausted(DataInputStream in) throws IOException {
        if (in.read() != -1) throw new EvidenceFormatException("Trailing build evidence payload bytes");
    }

    private static void requireExpectedKey(String value, String field) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_STRING_BYTES) {
            throw new IllegalArgumentException(field + " exceeds " + MAX_STRING_BYTES + " UTF-8 bytes");
        }
    }

    private static byte[] sha256(byte[] value) {
        MessageDigest digest = newSha256();
        return digest.digest(value);
    }

    private static String sha256Hex(String value) {
        byte[] digest = sha256(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static final class BoundedOutputStream extends OutputStream {
        private final int maximum;
        private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
        private int size;

        private BoundedOutputStream(int maximum) {
            this.maximum = maximum;
        }

        @Override
        public void write(int value) throws IOException {
            ensureCapacity(1);
            delegate.write(value);
            size++;
        }

        @Override
        public void write(byte[] value, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, value.length);
            ensureCapacity(length);
            delegate.write(value, offset, length);
            size += length;
        }

        private void ensureCapacity(int additional) throws IOException {
            if (additional > maximum - size) {
                throw new IOException("Build evidence payload exceeds " + maximum + " bytes");
            }
        }

        private byte[] toByteArray() {
            return delegate.toByteArray();
        }
    }
}
