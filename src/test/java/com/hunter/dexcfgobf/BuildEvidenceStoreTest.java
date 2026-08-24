package com.hunter.dexcfgobf;

import com.hunter.dexcfgobf.gradle.DexCfgObfuscatorPlugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public class BuildEvidenceStoreTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void cfgEvidenceRoundTripsEveryStatAndMethodReport() throws Exception {
        File evidence = new File(temporary.newFolder("intermediates-cfg"), "cfg.evidence");
        ObfuscatorStats expected = completeStats();

        BuildEvidenceStore.writeCfg(evidence, "post-fingerprint", "cfg-transform-digest", expected);

        Optional<BuildEvidenceStore.CfgEvidence> restored = BuildEvidenceStore.readCfg(
                evidence, "post-fingerprint", "cfg-transform-digest");
        assertTrue(restored.isPresent());
        assertTrue(BuildEvidenceStore.readCfg(evidence).isPresent());
        assertEquals("post-fingerprint", restored.get().getPostFingerprint());
        assertEquals("cfg-transform-digest", restored.get().getCfgTransformDigest());
        assertStatsEqual(expected, restored.get().getStats());

        // A consumer cannot mutate the snapshot retained by the evidence object.
        ObfuscatorStats mutableCopy = restored.get().getStats();
        mutableCopy.methodsObfuscated = 0;
        mutableCopy.methodReports.clear();
        assertEquals(expected.methodsObfuscated, restored.get().getStats().methodsObfuscated);
        assertEquals(1, restored.get().getStats().methodReports.size());
    }

    @Test
    public void stringEvidenceRoundTripsCoverageStatsAndOnlyPlaintextHashes() throws Exception {
        File evidence = new File(temporary.newFolder("intermediates-string"), "string.evidence");
        ObfuscatorStats expected = completeStats();
        expected.methodReports.clear();
        expected.stringCoverageStatus = "FULL";
        expected.stringPlaintextGateMode = "LIBRARY_JVM_RUNTIME_PAYLOAD";
        expected.stringDexFilesScanned = 0;
        String first = repeat('a', 64);
        String secondUppercase = repeat('B', 64);
        Set<String> hashes = new HashSet<>(Arrays.asList(first, secondUppercase));
        java.util.Map<String, Set<String>> ownerHashes = Collections.singletonMap(
                "com.example.Owner", hashes);

        BuildEvidenceStore.writeString(evidence, "audit-fingerprint", "string-transform-digest",
                expected, hashes, ownerHashes, Collections.singletonMap(
                        "com/example/Owner->value()Ljava/lang/String;", hashes),
                Collections.emptyMap());

        Optional<BuildEvidenceStore.StringEvidence> restored = BuildEvidenceStore.readString(
                evidence, "audit-fingerprint", "string-transform-digest");
        assertTrue(restored.isPresent());
        assertTrue(BuildEvidenceStore.readString(evidence).isPresent());
        assertEquals("audit-fingerprint", restored.get().getAuditFingerprint());
        assertEquals("string-transform-digest", restored.get().getStringTransformDigest());
        assertEquals("FULL", restored.get().getCoverageStatus());
        assertEquals(new HashSet<>(Arrays.asList(first, repeat('b', 64))),
                restored.get().getPlaintextSha256());
        assertTrue(restored.get().hasOwnerScope());
        assertEquals(6, restored.get().getFormatVersion());
        assertTrue(restored.get().hasSkipReasonStats());
        assertEquals(Collections.singleton("com.example.Owner"),
                restored.get().getModifiedOriginalClassNames());
        assertEquals(new HashSet<>(Arrays.asList(first, repeat('b', 64))),
                restored.get().getPlaintextSha256ByOriginalClass().get("com.example.Owner"));
        assertTrue(restored.get().hasMemberScope());
        assertEquals(new HashSet<>(Arrays.asList(first, repeat('b', 64))),
                restored.get().getPlaintextSha256ByOriginalMethod()
                        .get("com/example/Owner->value()Ljava/lang/String;"));
        assertStatsEqual(expected, restored.get().getStats());
        assertThrows(UnsupportedOperationException.class,
                () -> restored.get().getPlaintextSha256().clear());
        assertThrows(UnsupportedOperationException.class,
                () -> restored.get().getPlaintextSha256ByOriginalClass().clear());
        assertThrows(UnsupportedOperationException.class,
                () -> restored.get().getPlaintextSha256ByOriginalClass()
                        .get("com.example.Owner").clear());

        String raw = new String(Files.readAllBytes(evidence.toPath()), StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains("a plaintext that must not enter evidence"));
    }

    @Test
    public void fingerprintOrTransformDigestMismatchMakesEvidenceUnavailable() throws Exception {
        File root = temporary.newFolder("intermediates-mismatch");
        File cfg = new File(root, "cfg.evidence");
        File string = new File(root, "string.evidence");
        ObfuscatorStats stats = completeStats();
        BuildEvidenceStore.writeCfg(cfg, "post", "cfg-digest", stats);
        BuildEvidenceStore.writeString(string, "audit", "string-digest", stats,
                Collections.singleton(repeat('c', 64)), Collections.singletonMap(
                        "com.example.Owner", Collections.singleton(repeat('c', 64))),
                Collections.singletonMap("com/example/Owner->value()V",
                        Collections.singleton(repeat('c', 64))), Collections.emptyMap());

        assertFalse(BuildEvidenceStore.readCfg(cfg, "wrong-post", "cfg-digest").isPresent());
        assertFalse(BuildEvidenceStore.readCfg(cfg, "post", "wrong-digest").isPresent());
        assertFalse(BuildEvidenceStore.readString(string, "wrong-audit", "string-digest").isPresent());
        assertFalse(BuildEvidenceStore.readString(string, "audit", "wrong-digest").isPresent());
    }

    @Test
    public void cfgPendingMarkerRoundTripsAndRejectsWrongEvidenceKind() throws Exception {
        File root = temporary.newFolder("intermediates-pending");
        File pending = new File(root, "cfg.pending");
        File cfg = new File(root, "cfg.evidence");

        BuildEvidenceStore.writeCfgPending(pending, "pre-fingerprint", "cfg-digest");
        Optional<BuildEvidenceStore.CfgPendingEvidence> restored =
                BuildEvidenceStore.readCfgPending(pending);
        assertTrue(restored.isPresent());
        assertEquals("pre-fingerprint", restored.get().getPreFingerprint());
        assertEquals("cfg-digest", restored.get().getCfgTransformDigest());

        BuildEvidenceStore.writeCfg(cfg, "post", "cfg-digest", completeStats());
        BuildEvidenceStore.EvidenceFormatException wrongKind = assertThrows(
                BuildEvidenceStore.EvidenceFormatException.class,
                () -> BuildEvidenceStore.readCfgPending(cfg));
        assertTrue(wrongKind.getMessage().contains("Wrong build evidence kind"));
    }

    @Test
    public void missingEvidenceIsUnavailable() throws Exception {
        File absent = new File(temporary.newFolder("intermediates-absent"), "absent.evidence");

        assertFalse(BuildEvidenceStore.readCfg(absent, "post", "digest").isPresent());
        assertFalse(BuildEvidenceStore.readString(absent, "audit", "digest").isPresent());
    }

    @Test
    public void corruptionAndVersionMismatchFailExplicitly() throws Exception {
        File root = temporary.newFolder("intermediates-corruption");
        File corrupted = new File(root, "corrupted.evidence");
        File wrongVersion = new File(root, "wrong-version.evidence");
        BuildEvidenceStore.writeCfg(corrupted, "post", "digest", completeStats());
        BuildEvidenceStore.writeCfg(wrongVersion, "post", "digest", completeStats());

        byte[] corruptedBytes = Files.readAllBytes(corrupted.toPath());
        corruptedBytes[corruptedBytes.length - 1] ^= 0x01;
        Files.write(corrupted.toPath(), corruptedBytes);
        BuildEvidenceStore.EvidenceFormatException checksumFailure = assertThrows(
                BuildEvidenceStore.EvidenceFormatException.class,
                () -> BuildEvidenceStore.readCfg(corrupted, "post", "digest"));
        assertTrue(checksumFailure.getMessage().contains("checksum"));

        byte[] wrongVersionBytes = Files.readAllBytes(wrongVersion.toPath());
        ByteBuffer.wrap(wrongVersionBytes).putInt(Integer.BYTES, 99);
        Files.write(wrongVersion.toPath(), wrongVersionBytes);
        BuildEvidenceStore.EvidenceFormatException versionFailure = assertThrows(
                BuildEvidenceStore.EvidenceFormatException.class,
                () -> BuildEvidenceStore.readCfg(wrongVersion, "post", "digest"));
        assertTrue(versionFailure.getMessage().contains("version"));
    }

    @Test
    public void atomicRewriteReplacesOldRecordAndCleansTemporaryFile() throws Exception {
        File root = temporary.newFolder("intermediates-rewrite");
        File evidence = new File(root, "cfg.evidence");
        ObfuscatorStats first = completeStats();
        ObfuscatorStats second = completeStats();
        second.methodsObfuscated = 9001;

        BuildEvidenceStore.writeCfg(evidence, "post-one", "digest-one", first);
        BuildEvidenceStore.writeCfg(evidence, "post-two", "digest-two", second);

        assertFalse(BuildEvidenceStore.readCfg(evidence, "post-one", "digest-one").isPresent());
        Optional<BuildEvidenceStore.CfgEvidence> restored = BuildEvidenceStore.readCfg(
                evidence, "post-two", "digest-two");
        assertTrue(restored.isPresent());
        assertEquals(9001, restored.get().getStats().methodsObfuscated);
        try (Stream<java.nio.file.Path> files = Files.list(root.toPath())) {
            assertFalse(files.anyMatch(path -> path.getFileName().toString()
                    .startsWith(".build-evidence-")));
        }
    }

    @Test
    public void evidenceFileNamesCannotEscapeTheIntermediatesRoot() throws Exception {
        File root = temporary.newFolder("intermediates-names");
        File dexDir = temporary.newFolder("producer-dex");

        File cfg = BuildEvidenceStore.cfgEvidenceFile(root, dexDir);
        File pending = BuildEvidenceStore.cfgPendingFile(root, dexDir);
        File lock = BuildEvidenceStore.cfgLockFile(root, dexDir);
        File string = BuildEvidenceStore.stringEvidenceFile(root, "../../release");

        assertEquals(root.getCanonicalFile(), cfg.getParentFile().getCanonicalFile());
        assertEquals(root.getCanonicalFile(), string.getParentFile().getCanonicalFile());
        assertTrue(cfg.getName().matches("[0-9a-f]{64}\\.cfg\\.evidence"));
        assertTrue(pending.getName().matches("[0-9a-f]{64}\\.cfg\\.pending"));
        assertTrue(lock.getName().matches("[0-9a-f]{64}\\.cfg\\.lock"));
        assertTrue(string.getName().matches("[0-9a-f]{64}\\.string\\.evidence"));
    }

    @Test
    public void invalidPlaintextHashIsRejectedBeforeWriting() throws Exception {
        File evidence = new File(temporary.newFolder("intermediates-invalid-hash"),
                "string.evidence");

        assertThrows(IllegalArgumentException.class, () -> BuildEvidenceStore.writeString(
                evidence, "audit", "digest", completeStats(), Collections.singleton("secret"),
                Collections.singletonMap("com.example.Owner",
                        Collections.singleton("secret")),
                Collections.singletonMap("com/example/Owner->value()V",
                        Collections.singleton("secret")), Collections.emptyMap()));
        assertFalse(evidence.exists());
    }

    @Test
    public void legacyV2StringEvidenceIsReadableButExplicitlyHasNoOwnerScope() throws Exception {
        File evidence = new File(temporary.newFolder("intermediates-legacy-v2"),
                "string.evidence");
        Set<String> hashes = Collections.singleton(repeat('d', 64));
        BuildEvidenceStore.writeLegacyV2StringForTest(evidence, "audit", "digest",
                completeStats(), hashes);

        BuildEvidenceStore.StringEvidence restored =
                BuildEvidenceStore.readString(evidence, "audit", "digest").get();
        assertEquals(hashes, restored.getPlaintextSha256());
        assertFalse(restored.hasOwnerScope());
        assertTrue(restored.getModifiedOriginalClassNames().isEmpty());
        assertTrue(restored.getPlaintextSha256ByOriginalClass().isEmpty());
    }

    @Test
    public void legacyV3MemberScopeCannotSatisfyFiniteSkipReasonBudgets() throws Exception {
        File evidence = new File(temporary.newFolder("intermediates-legacy-v3"),
                "string.evidence");
        Set<String> hashes = Collections.singleton(repeat('e', 64));
        BuildEvidenceStore.writeLegacyV3StringForTest(evidence, "audit", "digest",
                completeStats(), hashes,
                Collections.singletonMap("com/example/Owner", hashes),
                Collections.singletonMap("com/example/Owner->value()V", hashes),
                Collections.emptyMap());

        BuildEvidenceStore.StringEvidence restored =
                BuildEvidenceStore.readString(evidence, "audit", "digest").get();
        assertEquals(3, restored.getFormatVersion());
        assertTrue(restored.hasOwnerScope());
        assertFalse(restored.hasSkipReasonStats());
        assertThrows(org.gradle.api.GradleException.class, () ->
                DexCfgObfuscatorPlugin.requireStringSkipReasonStats(
                        restored, 0, Integer.MAX_VALUE, "release", "application DEX"));
        DexCfgObfuscatorPlugin.requireStringSkipReasonStats(restored,
                Integer.MAX_VALUE, Integer.MAX_VALUE, "debug", "application DEX");
    }

    @Test
    public void partialCurrentSnapshotCannotCarryLegacyV3PastFiniteSkipBudget()
            throws Exception {
        File evidence = new File(temporary.newFolder("intermediates-partial-v3"),
                "string.evidence");
        String priorHash = repeat('e', 64);
        Set<String> priorHashes = Collections.singleton(priorHash);
        BuildEvidenceStore.writeLegacyV3StringForTest(evidence, "prior-audit", "digest",
                completeStats(), priorHashes,
                Collections.singletonMap("com/example/Prior", priorHashes),
                Collections.singletonMap("com/example/Prior->value()V", priorHashes),
                Collections.emptyMap());

        String currentHash = repeat('f', 64);
        Set<String> currentHashes = Collections.singleton(currentHash);
        Map<String, Set<String>> currentClasses = Collections.singletonMap(
                "com/example/Current", currentHashes);
        Map<String, Set<String>> currentMethods = Collections.singletonMap(
                "com/example/Current->value()V", currentHashes);
        Project project = ProjectBuilder.builder().withName("partial-current").build();
        Method merge = DexCfgObfuscatorPlugin.class.getDeclaredMethod(
                "mergePriorStringEvidence", Project.class, File.class, String.class,
                Set.class, Map.class, Map.class, Map.class, int.class, int.class,
                String.class, String.class);
        merge.setAccessible(true);

        InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                () -> merge.invoke(null, project, evidence, "digest", currentHashes,
                        currentClasses, currentMethods, Collections.emptyMap(), 0,
                        Integer.MAX_VALUE, "debug", "application DEX"));

        assertTrue(failure.getCause() instanceof GradleException);
        assertTrue(failure.getCause().getMessage().contains("predates skip-reason statistics"));
    }

    private static ObfuscatorStats completeStats() {
        ObfuscatorStats stats = new ObfuscatorStats();
        int value = 1;
        stats.dexProcessed = value++;
        stats.dexVerified = value++;
        stats.dexFailed = value++;
        stats.classesScanned = value++;
        stats.methodsScanned = value++;
        stats.methodsObfuscated = value++;
        stats.methodsFlattened = value++;
        stats.methodsReordered = value++;
        stats.reorderedTryCatch = value++;
        stats.reorderedRegConflict = value++;
        stats.reorderedVerifierRisk = value++;
        stats.methodsSkippedNotIncluded = value++;
        stats.methodsSkippedTryCatch = value++;
        stats.methodsSkippedTooSmall = value++;
        stats.methodsSkippedTooLarge = value++;
        stats.methodsSkippedUnsupported = value++;
        stats.methodsSkippedAlreadyObfuscated = value++;
        stats.methodsSkippedVerifierAnalysis = value++;
        stats.methodsSkippedRegisterBudget = value++;
        stats.cfgResolvedClassWideOwners = value++;
        stats.cfgResolvedMemberOnlyOwners = value++;
        stats.cfgResolvedMemberMethods = value++;
        stats.cfgRequiredMethodsResolved = value++;
        stats.cfgRequiredMethodsScanned = value++;
        stats.cfgRequiredMethodsObfuscated = value++;
        stats.switchesPadded = value++;
        stats.switchCasesBefore = value++;
        stats.switchCasesAfter = value++;
        stats.fakeSwitchCases = value++;
        stats.symbolSwitchCases = value++;
        stats.regionalDispatchers = value++;
        stats.reachableAliasCases = value++;
        stats.stateSharedMethods = value++;
        stats.stringEncryptionEnabled = true;
        stats.stringEncryptionMode = "BYTES";
        stats.stringCoverageStatus = "PARTIAL_OR_FULL";
        stats.stringClassesVisited = value++;
        stats.stringClassesModified = value++;
        stats.stringConstantsEncrypted = value++;
        stats.stringConstantsSkipped = value++;
        stats.stringSkippedWhitespace = value++;
        stats.stringSkippedTooLarge = value++;
        stats.stringSkippedInvalidUnicode = value++;
        stats.stringSkippedFiltered = value++;
        stats.stringUnsupportedConstants = value++;
        stats.stringIdentityCiphertexts = value++;
        stats.stringPlaintextVerified = true;
        stats.stringDexFilesScanned = value++;
        stats.stringPoolEntriesScanned = value++;
        stats.stringPlaintextHashesTracked = value++;
        stats.stringPlaintextGateMode = "RUNTIME_PAYLOAD";
        stats.stringPlaintextLeaks = value++;
        stats.stringPlaintextLeakOccurrences = value++;
        stats.stringRuntimePlaintextLeaks = value++;
        stats.stringRuntimePlaintextLeakOccurrences = value++;
        stats.stringWholePoolPlaintextCollisions = value++;
        stats.stringWholePoolPlaintextCollisionOccurrences = value++;
        stats.stringConstStringReferencesScanned = value++;
        stats.stringStaticStringValuesScanned = value++;
        stats.stringAnnotationStringValuesScanned = value++;
        stats.stringCallSiteStringValuesScanned = value++;
        stats.stringScopedRuntimePlaintextLeaks = value++;
        stats.stringScopedRuntimePlaintextLeakOccurrences = value++;
        stats.stringGlobalRuntimeFallbackHashesTracked = value++;
        stats.stringGlobalRuntimeFallbackPlaintextLeaks = value++;
        stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = value++;
        stats.stringOwnerRuntimePlaintextCollisions = value++;
        stats.stringOwnerRuntimePlaintextCollisionOccurrences = value++;
        stats.stringGlobalRuntimePlaintextCollisions = value++;
        stats.stringGlobalRuntimePlaintextCollisionOccurrences = value++;
        stats.stringTargetClassesResolved = value++;
        stats.stringTargetClassesScanned = value++;
        stats.stringTargetMethodsResolved = value++;
        stats.stringTargetMethodsScanned = value++;
        stats.stringTargetFieldsResolved = value++;
        stats.stringTargetFieldsScanned = value++;
        stats.stringR8MappedMethodSites = value++;
        stats.stringR8RemovedMethodSites = value++;
        stats.stringR8IdentityMethodSites = value++;
        stats.stringR8FallbackMethodSites = value++;
        stats.stringR8MappedFieldProvenance = value++;
        stats.stringR8RemovedFieldProvenance = value++;
        stats.stringR8IdentityFieldProvenance = value++;
        stats.stringR8FallbackFieldProvenance = value++;
        stats.stringRemovedOriginalSiteHashesTracked = value++;
        stats.stringIdentityFieldProvenanceResolved = value++;
        stats.stringIdentityFieldProvenanceScanned = value++;
        stats.stringStructuralAnnotationStringValuesScanned = value++;
        stats.stringStructuralAnnotationPlaintextCollisions = value++;
        stats.stringStructuralAnnotationPlaintextCollisionOccurrences = value++;
        stats.stringMinEncryptedStrings = value++;
        stats.stringMinModifiedClasses = value++;
        stats.stringMaxSkippedStrings = value++;
        stats.stringMaxUnsafeSkippedStrings = value++;
        stats.stringMaxFilteredStrings = value++;
        stats.stringFailOnUnknownCoverage = true;
        stats.stringVerifyFinalDex = false;
        stats.stringFailOnPlaintextLeak = true;
        stats.stringFailOnUnsupportedConstants = false;
        stats.stringFailOnUnprotectedDecryptor = true;
        stats.artifactFingerprint = "artifact-meta";
        stats.cfgTransformDigest = "cfg-meta";
        stats.stringTransformDigest = "string-meta";
        stats.evidenceSource = "MIXED";
        stats.originalDexBytes = 1_234_567_890L;
        stats.outputDexBytes = 1_345_678_901L;
        stats.methodReports.add(MethodReport.restore(
                "classes2.dex", "Lexample/Foo;", "work", "(IJ)Ljava/lang/String;",
                "flattened", "flatten_safe", "regional", 11, 29, 17, 43,
                5, 9, true, true, false, true, 4, 2, 3, 7,
                4, 1, 2, 3, 2));
        return stats;
    }

    private static void assertStatsEqual(ObfuscatorStats expected, ObfuscatorStats actual)
            throws Exception {
        // Schema guard: adding a public summary/gate field requires evidence serialization too.
        for (Field field : ObfuscatorStats.class.getFields()) {
            if ("methodReports".equals(field.getName())) continue;
            assertEquals("ObfuscatorStats." + field.getName(), field.get(expected), field.get(actual));
        }
        assertEquals(expected.methodReports.size(), actual.methodReports.size());
        for (int i = 0; i < expected.methodReports.size(); i++) {
            assertMethodReportEqual(expected.methodReports.get(i), actual.methodReports.get(i));
        }
    }

    private static void assertMethodReportEqual(MethodReport expected, MethodReport actual)
            throws Exception {
        for (Field field : MethodReport.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) continue;
            field.setAccessible(true);
            assertEquals("MethodReport." + field.getName(), field.get(expected), field.get(actual));
        }
    }

    private static String repeat(char value, int count) {
        char[] result = new char[count];
        Arrays.fill(result, value);
        return new String(result);
    }
}
