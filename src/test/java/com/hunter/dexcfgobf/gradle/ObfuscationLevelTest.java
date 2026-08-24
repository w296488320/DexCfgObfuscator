package com.hunter.dexcfgobf.gradle;

import com.hunter.dexcfgobf.ObfuscatorConfig;
import com.hunter.dexcfgobf.ObfuscatorStats;
import com.hunter.dexcfgobf.string.StringClassConstantPoolCompactor;
import com.hunter.dexcfgobf.string.StringPlaintextVerifier;

import org.gradle.api.GradleException;
import org.junit.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

public class ObfuscationLevelTest {

    @Test
    public void exposesStableLevelsAndDefaultsToMedium() {
        assertEquals(1, ObfuscationLevel.LOW.getDepth());
        assertEquals(2, ObfuscationLevel.MEDIUM.getDepth());
        assertEquals(3, ObfuscationLevel.HIGH.getDepth());

        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension();
        assertTrue(extension.getEnabled());
        assertTrue(extension.getEnabledVariants().isEmpty());
        assertTrue(extension.getStringEncryption().getFailOnUnsupportedStringConstants());
        assertEquals(1, extension.getStringEncryption().getMinEncryptedStrings());
        assertEquals(1, extension.getStringEncryption().getMinModifiedClasses());
        assertEquals(0, extension.getStringEncryption().getMaxUnsafeSkippedStrings());
        assertEquals(0, extension.getStringEncryption().getMaxFilteredStrings());
        assertTrue(extension.getStringEncryption().getFailOnUnknownCoverage());
        assertEquals(Collections.singletonList("release"),
                extension.getStringEncryption().getFailOnUnknownCoverageVariants());
        assertTrue(extension.getStringEncryption().getVerifyFinalDex());
        assertTrue(extension.getStringEncryption().getFailOnPlaintextLeak());
        assertTrue(extension.getStringEncryption().getFailOnUnprotectedDecryptor());
        assertFalse(extension.getStringEncryption().getStrictWholeStringPool());
        assertTrue(extension.getStringEncryption().getEnabledVariants().isEmpty());
        assertTrue(extension.getStringEncryption().getDependencyEvidenceProjects().isEmpty());
        assertTrue(extension.getStringEncryption().getDependencyEvidenceVariants().isEmpty());
        assertEquals(ObfuscationLevel.MEDIUM, extension.getLevel());
        assertEquals(0, extension.getMinObfuscatedMethods());
        assertEquals(0, extension.getMinFlattenedMethods());
        assertEquals(0.0d, extension.getMinObfuscatedRatio(), 0.0d);
        assertEquals(100.0d, extension.getMaxSizeIncreasePercent(), 0.0d);
    }

    @Test
    public void selectsCfgByExactVariantOrBuildTypeWithoutTaskNameHeuristics() {
        assertFalse(DexCfgObfuscatorPlugin.isCfgEnabledForVariant(false,
                Collections.emptyList(), "release", "release"));
        assertTrue(DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                Collections.emptyList(), "debug", "debug"));
        assertTrue(DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                Collections.singletonList("RELEASE"), "freeRelease", "release"));
        assertTrue(DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                Collections.singletonList("FREERELEASE"), "freeRelease", "release"));
        assertFalse(DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                Collections.singletonList("free"), "freeRelease", "release"));
        assertFalse(DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                Collections.singletonList("releaseCandidate"), "freeRelease", "release"));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                        Collections.singletonList("  "), "release", "release"));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                        Collections.singletonList(null), "release", "release"));
    }

    @Test
    public void acceptsScalarCollectionAndArrayVariantAndDependencyDslValues() {
        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension();
        extension.enabledVariants("release");
        assertEquals(Collections.singletonList("release"), extension.getEnabledVariants());
        extension.enabledVariants(Arrays.asList("debug", "release"));
        assertEquals(Arrays.asList("debug", "release"), extension.getEnabledVariants());
        extension.enabledVariants(new String[]{"freeRelease"});
        assertEquals(Collections.singletonList("freeRelease"), extension.getEnabledVariants());

        StringEncryptionExtension strings = extension.getStringEncryption();
        strings.enabledVariants("hardened");
        assertEquals(Collections.singletonList("hardened"), strings.getEnabledVariants());
        strings.enabledVariants(new String[]{"debug", "release"});
        assertEquals(Arrays.asList("debug", "release"), strings.getEnabledVariants());
        strings.dependencyEvidenceProjects(":IFAA");
        assertEquals(Collections.singletonList(":IFAA"),
                strings.getDependencyEvidenceProjects());
        strings.dependencyEvidenceProjects(new String[]{":IFAA", ":security"});
        assertEquals(Arrays.asList(":IFAA", ":security"),
                strings.getDependencyEvidenceProjects());
        strings.dependencyEvidenceVariants("release");
        assertEquals(Collections.singletonList("release"),
                strings.getDependencyEvidenceVariants());
        strings.failOnUnknownCoverageVariants(new String[]{"debug", "release"});
        assertEquals(Arrays.asList("debug", "release"),
                strings.getFailOnUnknownCoverageVariants());
        strings.failOnUnknownCoverageVariants(new String[]{null});
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.isVariantSelected(
                        strings.getFailOnUnknownCoverageVariants(), "debug", "debug", "selector"));
        extension.enabledVariants((Object) null);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.isCfgEnabledForVariant(true,
                        extension.getEnabledVariants(), "debug", "debug"));
    }

    @Test
    public void selectsIndependentStringGatesByExactVariantOrBuildType() {
        assertTrue(DexCfgObfuscatorPlugin.isVariantSelected(Collections.emptyList(),
                "debug", "debug", "selector"));
        assertTrue(DexCfgObfuscatorPlugin.isVariantSelected(
                Collections.singletonList("RELEASE"), "freeRelease", "release", "selector"));
        assertTrue(DexCfgObfuscatorPlugin.isVariantSelected(
                Collections.singletonList("freeRelease"), "freeRelease", "release", "selector"));
        assertFalse(DexCfgObfuscatorPlugin.isVariantSelected(
                Collections.singletonList("free"), "freeRelease", "release", "selector"));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.isVariantSelected(Collections.singletonList(" "),
                        "debug", "debug", "selector"));
    }

    @Test
    public void excludedApplicationStringVariantKeepsStringGatesDisabled() {
        StringEncryptionExtension strings = new StringEncryptionExtension();
        strings.enabled(true);
        strings.enabledVariants("release");
        boolean debugStringStageEnabled = strings.getEnabled()
                && DexCfgObfuscatorPlugin.isVariantSelected(strings.getEnabledVariants(),
                "debug", "debug", "stringEncryption.enabledVariants");
        assertFalse(debugStringStageEnabled);

        ObfuscatorStats stats = new ObfuscatorStats();
        ObfuscatorConfig config = new ObfuscatorConfig();
        DexCfgObfuscatorPlugin.applyVariantStringConfigurationToStats(
                debugStringStageEnabled, strings, stats, true);
        assertEquals("DISABLED", stats.stringCoverageStatus);
        assertEquals(Integer.MAX_VALUE, stats.stringMaxUnsafeSkippedStrings);
        assertFalse(stats.stringFailOnUnknownCoverage);

        // Global strings.enabled remains true, but this excluded variant must not require string
        // evidence, a final-DEX plaintext result, or decryptor CFG coverage.
        DexCfgObfuscatorPlugin.enforceVariantStringGates(
                debugStringStageEnabled, strings, config, stats, "debug", true);

        DexCfgObfuscatorPlugin.applyVariantStringConfigurationToStats(
                true, strings, stats, true);
        assertEquals(0, stats.stringMaxUnsafeSkippedStrings);
        assertTrue(stats.stringFailOnUnknownCoverage);
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.enforceVariantStringGates(
                        true, strings, config, stats, "release", true));
    }

    @Test
    public void copiesConfiguredQualityBudgetsIntoCoreConfig() {
        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension();
        extension.setMinObfuscatedMethods(17);
        extension.setMinFlattenedMethods(5);
        extension.setMinObfuscatedRatio(0.625d);
        extension.setMaxSizeIncreasePercent(42.5d);
        ObfuscatorConfig config = new ObfuscatorConfig();

        DexCfgObfuscatorPlugin.applyQualityBudgets(extension, config);

        assertEquals(17, config.minObfuscatedMethods);
        assertEquals(5, config.minFlattenedMethods);
        assertEquals(0.625d, config.minObfuscatedRatio, 0.0d);
        assertEquals(42.5d, config.maxSizeIncreasePercent, 0.0d);
    }

    @Test
    public void rejectsInvalidQualityBudgets() {
        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension();
        ObfuscatorConfig config = new ObfuscatorConfig();

        extension.setMinObfuscatedMethods(-1);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.applyQualityBudgets(extension, config));

        extension.setMinObfuscatedMethods(0);
        extension.setMinFlattenedMethods(-1);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.applyQualityBudgets(extension, config));

        extension.setMinFlattenedMethods(0);
        extension.setMinObfuscatedRatio(1.01d);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.applyQualityBudgets(extension, config));

        extension.setMinObfuscatedRatio(0.0d);
        extension.setMaxSizeIncreasePercent(Double.NaN);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.applyQualityBudgets(extension, config));
    }

    @Test
    public void defaultBridgeIsStablePerProjectAndDoesNotCollideAcrossModules() {
        String app = DexCfgObfuscatorPlugin.defaultBridgeClass("com.example", ":app");
        String appAgain = DexCfgObfuscatorPlugin.defaultBridgeClass("com.example", ":app");
        String library = DexCfgObfuscatorPlugin.defaultBridgeClass("com.example", ":feature");
        assertEquals(app, appAgain);
        org.junit.Assert.assertNotEquals(app, library);
        assertTrue(app.matches("com\\.example\\.DexStringDecryptor_[0-9a-f]{8}"));
    }

    @Test
    public void wiresOneGeneratedRulesProviderToAppAndLibraryVariants() {
        Object appRules = new Object();
        ProtectionVariant app = new ProtectionVariant();
        DexCfgObfuscatorPlugin.wireStringProtectionRules(app, appRules, false);
        assertEquals(1, app.proguardFiles.values.size());
        assertSame(appRules, app.proguardFiles.values.get(0));
        assertTrue(app.consumerProguardFiles.values.isEmpty());

        Object libraryRules = new Object();
        ProtectionVariant library = new ProtectionVariant();
        DexCfgObfuscatorPlugin.wireStringProtectionRules(library, libraryRules, true);
        assertEquals(1, library.proguardFiles.values.size());
        assertEquals(1, library.consumerProguardFiles.values.size());
        assertSame(libraryRules, library.proguardFiles.values.get(0));
        assertSame(libraryRules, library.consumerProguardFiles.values.get(0));
    }

    @Test
    public void detectsWhenDecryptorIsExcludedFromCfgCoverage() {
        assertTrue(DexCfgObfuscatorPlugin.isClassCoveredByCfg("com.example.Cipher",
                java.util.Collections.singletonList("com.example"),
                java.util.Collections.singletonList("com.example.other")));
        assertFalse(DexCfgObfuscatorPlugin.isClassCoveredByCfg("com.example.stringfog.Cipher",
                java.util.Collections.singletonList("com.example"),
                java.util.Collections.singletonList("com.example.stringfog")));
        assertFalse(DexCfgObfuscatorPlugin.isClassCoveredByCfg("com.examples.Cipher",
                java.util.Collections.singletonList("com.example"),
                java.util.Collections.emptyList()));
    }

    @Test
    public void zeroEncryptedSitesNeedNoDecryptorCfgButEncryptedEvidenceCannotUseEmptyScope() {
        StringEncryptionExtension strings = new StringEncryptionExtension();
        strings.setEnabled(true);
        strings.setFailOnUnprotectedDecryptor(true);
        ObfuscatorConfig config = new ObfuscatorConfig();

        DexCfgObfuscatorPlugin.configureRequiredDecryptorMethods(config,
                Collections.emptySet(), false, null, "debug");
        assertTrue(config.requiredResolvedIncludeMethods.isEmpty());

        ObfuscatorStats noSites = new ObfuscatorStats();
        DexCfgObfuscatorPlugin.enforceRequiredDecryptorCfg(
                strings, config, noSites, "debug");

        ObfuscatorStats inconsistentEvidence = new ObfuscatorStats();
        inconsistentEvidence.stringConstantsEncrypted = 1;
        GradleException failure = assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.enforceRequiredDecryptorCfg(
                        strings, config, inconsistentEvidence, "debug"));
        assertTrue(failure.getMessage().contains("no generated decryptor call"));
    }

    @Test
    public void staticFieldProvenanceUsesClassInitializerAsTheOnlyFinalGateSite() {
        String owner = "fixture/StaticValues";
        String hash = StringPlaintextVerifier.sha256("static-secret");
        Set<String> hashes = Collections.singleton(hash);
        Map<String, Set<String>> classes = Collections.singletonMap(owner, hashes);
        Map<String, Set<String>> methods = Collections.singletonMap(
                owner + "-><clinit>()V", hashes);
        Map<String, Set<String>> fields = Collections.singletonMap(
                owner + "->SECRET", hashes);

        DexCfgObfuscatorPlugin.FinalStringScope scope =
                DexCfgObfuscatorPlugin.resolveFinalStringScope(
                        hashes, classes, methods, fields, false, null, "debug");

        assertEquals(methods, scope.getPlaintextHashesByFinalMethod());
        assertTrue(scope.getPlaintextHashesByFinalField().isEmpty());
        assertTrue(scope.getGlobalRuntimeFallbackHashes().isEmpty());
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.resolveFinalStringScope(
                        hashes, classes, Collections.emptyMap(), fields,
                        false, null, "debug"));
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.resolveFinalStringScope(
                        hashes, classes, Collections.singletonMap(
                                owner + "->unrelated()V", hashes), fields,
                        false, null, "debug"));
    }

    @Test
    public void r8UnknownSitesUseGlobalFallbackAndRemovedPseudoOwnerIsAffirmativeRemoval()
            throws Exception {
        String exactHash = StringPlaintextVerifier.sha256("exact");
        String identityHash = StringPlaintextVerifier.sha256("identity-omitted");
        String removedHash = StringPlaintextVerifier.sha256("removed");
        Set<String> all = new HashSet<>(Arrays.asList(
                exactHash, identityHash, removedHash));
        Map<String, Set<String>> classes = new LinkedHashMap<>();
        classes.put("fixture/Mapped", new HashSet<>(Arrays.asList(exactHash, identityHash)));
        classes.put("fixture/Removed", Collections.singleton(removedHash));
        Map<String, Set<String>> methods = new LinkedHashMap<>();
        methods.put("fixture/Mapped->kept()V", Collections.singleton(exactHash));
        methods.put("fixture/Mapped->identityOmitted()V",
                Collections.singleton(identityHash));
        methods.put("fixture/Removed->gone()V", Collections.singleton(removedHash));

        Path mapping = Files.createTempFile("r8-string-fallback-", ".txt");
        try {
            Files.write(mapping, Arrays.asList(
                    "fixture.Mapped -> a:",
                    "    void kept() -> b",
                    "fixture.Removed -> R8$$REMOVED$$CLASS$$7:"),
                    StandardCharsets.UTF_8);

            DexCfgObfuscatorPlugin.FinalStringScope scope =
                    DexCfgObfuscatorPlugin.resolveFinalStringScope(
                            all, classes, methods, Collections.emptyMap(), true,
                            mapping.toFile(), "release");

            assertEquals(Collections.singleton(exactHash),
                    scope.getPlaintextHashesByFinalMethod().get("a->b"));
            assertEquals(Collections.singleton(identityHash),
                    scope.getGlobalRuntimeFallbackHashes());
            assertEquals(Collections.singleton(removedHash),
                    scope.getRemovedOriginalSiteHashes());
            assertEquals(1, scope.getR8MappedMethodSites());
            assertEquals(1, scope.getR8RemovedMethodSites());
            assertEquals(0, scope.getR8IdentityMethodSites());
            assertEquals(1, scope.getR8FallbackMethodSites());
            assertTrue(scope.getPlaintextHashesByFinalClass().containsKey("a"));
            assertFalse(scope.getPlaintextHashesByFinalClass().containsKey(
                    "R8$$REMOVED$$CLASS$$7"));
            assertTrue(scope.getPlaintextHashesByFinalField().isEmpty());
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void r8CompanionsClassifyMethodsAndFieldProvenanceWithoutLeakingNames()
            throws Exception {
        String mappedMethodHash = StringPlaintextVerifier.sha256("mapped-method");
        String removedMethodHash = StringPlaintextVerifier.sha256("removed-method");
        String identityMethodHash = StringPlaintextVerifier.sha256("identity-method");
        String fallbackMethodHash = StringPlaintextVerifier.sha256("fallback-method");
        String mappedFieldHash = StringPlaintextVerifier.sha256("mapped-field");
        String removedFieldHash = StringPlaintextVerifier.sha256("removed-field");
        String identityFieldHash = StringPlaintextVerifier.sha256("identity-field");
        String fallbackFieldHash = StringPlaintextVerifier.sha256("fallback-field");
        Set<String> fieldHashes = new HashSet<>(Arrays.asList(mappedFieldHash,
                removedFieldHash, identityFieldHash, fallbackFieldHash));
        Set<String> all = new HashSet<>(Arrays.asList(mappedMethodHash,
                removedMethodHash, identityMethodHash, fallbackMethodHash,
                mappedFieldHash, removedFieldHash, identityFieldHash, fallbackFieldHash));
        Map<String, Set<String>> classes = Collections.singletonMap("fixture/Scope", all);
        Map<String, Set<String>> methods = new LinkedHashMap<>();
        methods.put("fixture/Scope->mapped()V", Collections.singleton(mappedMethodHash));
        methods.put("fixture/Scope->gone()V", Collections.singleton(removedMethodHash));
        methods.put("fixture/Scope->identity(Ljava/lang/String;)V",
                Collections.singleton(identityMethodHash));
        methods.put("fixture/Scope->unknown()V", Collections.singleton(fallbackMethodHash));
        methods.put("fixture/Scope-><clinit>()V", fieldHashes);
        Map<String, Set<String>> fields = new LinkedHashMap<>();
        fields.put("fixture/Scope->MAPPED_VALUE", Collections.singleton(mappedFieldHash));
        fields.put("fixture/Scope->REMOVED_VALUE", Collections.singleton(removedFieldHash));
        fields.put("fixture/Scope->IDENTITY_VALUE", Collections.singleton(identityFieldHash));
        fields.put("fixture/Scope->UNKNOWN_VALUE", Collections.singleton(fallbackFieldHash));

        Path directory = Files.createTempDirectory("r8-string-classifier-");
        Path mapping = directory.resolve("mapping.txt");
        Path usage = directory.resolve("usage.txt");
        Path seeds = directory.resolve("seeds.txt");
        try {
            Files.write(mapping, Arrays.asList(
                    "fixture.Scope -> x:",
                    "    void mapped() -> a",
                    "    java.lang.String MAPPED_VALUE -> b"), StandardCharsets.UTF_8);
            Files.write(usage, Arrays.asList(
                    "fixture.Scope:",
                    "    void gone()",
                    "    static final java.lang.String REMOVED_VALUE"),
                    StandardCharsets.UTF_8);
            Files.write(seeds, Arrays.asList(
                    "fixture.Scope: void identity(java.lang.String)",
                    "fixture.Scope: java.lang.String IDENTITY_VALUE"),
                    StandardCharsets.UTF_8);

            DexCfgObfuscatorPlugin.FinalStringScope scope =
                    DexCfgObfuscatorPlugin.resolveFinalStringScope(
                            all, classes, methods, fields, true,
                            mapping.toFile(), "release");

            assertEquals(Collections.singleton(mappedMethodHash),
                    scope.getPlaintextHashesByFinalMethod().get("x->a"));
            assertEquals(Collections.singleton(identityMethodHash),
                    scope.getPlaintextHashesByFinalMethod().get(
                            "x->identity(Ljava/lang/String;)V"));
            assertEquals(new HashSet<>(Arrays.asList(mappedFieldHash, identityFieldHash)),
                    scope.getPlaintextHashesByFinalMethod().get("x-><clinit>()V"));
            assertEquals(new HashSet<>(Arrays.asList(fallbackMethodHash, removedFieldHash,
                            fallbackFieldHash)),
                    scope.getGlobalRuntimeFallbackHashes());
            assertEquals(Collections.singleton(removedMethodHash),
                    scope.getRemovedOriginalSiteHashes());
            assertEquals(Collections.singleton(
                    "x->IDENTITY_VALUE:Ljava/lang/String;"),
                    scope.getIdentityFieldProvenanceTargets());
            assertTrue(scope.getPlaintextHashesByFinalField().isEmpty());
            assertEquals(1, scope.getR8MappedMethodSites());
            assertEquals(1, scope.getR8RemovedMethodSites());
            assertEquals(1, scope.getR8IdentityMethodSites());
            assertEquals(1, scope.getR8FallbackMethodSites());
            assertEquals(1, scope.getR8MappedFieldProvenance());
            assertEquals(0, scope.getR8RemovedFieldProvenance());
            assertEquals(1, scope.getR8IdentityFieldProvenance());
            assertEquals(2, scope.getR8FallbackFieldProvenance());
        } finally {
            Files.deleteIfExists(seeds);
            Files.deleteIfExists(usage);
            Files.deleteIfExists(mapping);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void removedOrPseudoFieldWithUnknownClinitUsesGlobalFallback()
            throws Exception {
        String usageHash = StringPlaintextVerifier.sha256("usage-removed-field");
        String pseudoHash = StringPlaintextVerifier.sha256("pseudo-mapped-field");
        Set<String> all = new HashSet<>(Arrays.asList(usageHash, pseudoHash));
        Map<String, Set<String>> methods = Collections.singletonMap(
                "fixture/Fields-><clinit>()V", all);
        Map<String, Set<String>> fields = new LinkedHashMap<>();
        fields.put("fixture/Fields->USAGE_GONE", Collections.singleton(usageHash));
        fields.put("fixture/Fields->PSEUDO", Collections.singleton(pseudoHash));

        Path directory = Files.createTempDirectory("r8-field-unknown-clinit-");
        Path mapping = directory.resolve("mapping.txt");
        Path usage = directory.resolve("usage.txt");
        try {
            Files.write(mapping, Arrays.asList(
                    "fixture.Fields -> x:",
                    "container.RemovedHolder -> R8$$REMOVED$$CLASS$$19:",
                    "    java.lang.String fixture.Fields.PSEUDO -> z"),
                    StandardCharsets.UTF_8);
            Files.write(usage, Arrays.asList(
                    "fixture.Fields:",
                    "    static final java.lang.String USAGE_GONE"),
                    StandardCharsets.UTF_8);

            DexCfgObfuscatorPlugin.FinalStringScope scope =
                    DexCfgObfuscatorPlugin.resolveFinalStringScope(
                            all, Collections.singletonMap("fixture/Fields", all),
                            methods, fields, true, mapping.toFile(), "release");

            assertEquals(all, scope.getGlobalRuntimeFallbackHashes());
            assertTrue(scope.getRemovedOriginalSiteHashes().isEmpty());
            assertTrue(scope.getPlaintextHashesByFinalMethod().isEmpty());
            assertEquals(0, scope.getR8RemovedFieldProvenance());
            assertEquals(2, scope.getR8FallbackFieldProvenance());
        } finally {
            Files.deleteIfExists(usage);
            Files.deleteIfExists(mapping);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void wholeClassOrExplicitClinitRemovalEliminatesFieldDecryptSite()
            throws Exception {
        String classHash = StringPlaintextVerifier.sha256("whole-class-removed-field");
        String clinitHash = StringPlaintextVerifier.sha256("clinit-removed-field");
        String pseudoClinitHash = StringPlaintextVerifier.sha256("pseudo-clinit-field");
        Set<String> all = new HashSet<>(Arrays.asList(
                classHash, clinitHash, pseudoClinitHash));
        Map<String, Set<String>> classes = new LinkedHashMap<>();
        classes.put("fixture/ClassGone", Collections.singleton(classHash));
        classes.put("fixture/ClinitGone", Collections.singleton(clinitHash));
        classes.put("fixture/PseudoClinit", Collections.singleton(pseudoClinitHash));
        Map<String, Set<String>> methods = new LinkedHashMap<>();
        methods.put("fixture/ClassGone-><clinit>()V", Collections.singleton(classHash));
        methods.put("fixture/ClinitGone-><clinit>()V", Collections.singleton(clinitHash));
        methods.put("fixture/PseudoClinit-><clinit>()V",
                Collections.singleton(pseudoClinitHash));
        Map<String, Set<String>> fields = new LinkedHashMap<>();
        fields.put("fixture/ClassGone->VALUE", Collections.singleton(classHash));
        fields.put("fixture/ClinitGone->VALUE", Collections.singleton(clinitHash));
        fields.put("fixture/PseudoClinit->VALUE", Collections.singleton(pseudoClinitHash));

        Path directory = Files.createTempDirectory("r8-field-removed-clinit-");
        Path mapping = directory.resolve("mapping.txt");
        Path usage = directory.resolve("usage.txt");
        try {
            Files.write(mapping, Arrays.asList(
                    "fixture.ClassGone -> x:",
                    "fixture.ClinitGone -> y:",
                    "    java.lang.String VALUE -> z",
                    "fixture.PseudoClinit -> p:",
                    "    java.lang.String VALUE -> q",
                    "container.RemovedHolder -> R8$$REMOVED$$CLASS$$21:",
                    "    void fixture.PseudoClinit.<clinit>() -> a"),
                    StandardCharsets.UTF_8);
            Files.write(usage, Arrays.asList(
                    "fixture.ClassGone",
                    "fixture.ClinitGone:",
                    "    static void <clinit>()"), StandardCharsets.UTF_8);

            DexCfgObfuscatorPlugin.FinalStringScope scope =
                    DexCfgObfuscatorPlugin.resolveFinalStringScope(
                            all, classes, methods, fields, true,
                            mapping.toFile(), "release");

            assertEquals(all, scope.getRemovedOriginalSiteHashes());
            assertTrue(scope.getGlobalRuntimeFallbackHashes().isEmpty());
            assertTrue(scope.getPlaintextHashesByFinalMethod().isEmpty());
            assertEquals(3, scope.getR8RemovedFieldProvenance());
            assertEquals(0, scope.getR8FallbackFieldProvenance());
        } finally {
            Files.deleteIfExists(usage);
            Files.deleteIfExists(mapping);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void sameHashAtRemovedAndLiveFieldSitesKeepsTheLiveGate() throws Exception {
        String mappedHash = StringPlaintextVerifier.sha256("removed-and-mapped-field");
        String fallbackHash = StringPlaintextVerifier.sha256("removed-and-unknown-field");
        Set<String> all = new HashSet<>(Arrays.asList(mappedHash, fallbackHash));
        Map<String, Set<String>> classes = new LinkedHashMap<>();
        classes.put("fixture/Mapped", Collections.singleton(mappedHash));
        classes.put("fixture/RemovedMappedTwin", Collections.singleton(mappedHash));
        classes.put("fixture/Unknown", Collections.singleton(fallbackHash));
        classes.put("fixture/RemovedFallbackTwin", Collections.singleton(fallbackHash));
        Map<String, Set<String>> methods = new LinkedHashMap<>();
        Map<String, Set<String>> fields = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> entry : classes.entrySet()) {
            methods.put(entry.getKey() + "-><clinit>()V", entry.getValue());
            fields.put(entry.getKey() + "->VALUE", entry.getValue());
        }

        Path directory = Files.createTempDirectory("r8-field-live-twins-");
        Path mapping = directory.resolve("mapping.txt");
        Path usage = directory.resolve("usage.txt");
        try {
            Files.write(mapping, Arrays.asList(
                    "fixture.Mapped -> a:",
                    "    java.lang.String VALUE -> b",
                    "fixture.RemovedMappedTwin -> c:",
                    "fixture.Unknown -> d:",
                    "fixture.RemovedFallbackTwin -> e:"), StandardCharsets.UTF_8);
            Files.write(usage, Arrays.asList(
                    "fixture.RemovedMappedTwin",
                    "fixture.RemovedFallbackTwin"), StandardCharsets.UTF_8);

            DexCfgObfuscatorPlugin.FinalStringScope scope =
                    DexCfgObfuscatorPlugin.resolveFinalStringScope(
                            all, classes, methods, fields, true,
                            mapping.toFile(), "release");

            assertEquals(Collections.singleton(mappedHash),
                    scope.getPlaintextHashesByFinalMethod().get("a-><clinit>()V"));
            assertEquals(Collections.singleton(fallbackHash),
                    scope.getGlobalRuntimeFallbackHashes());
            assertTrue("a hash with any live mapped/fallback site must not be skippable",
                    scope.getRemovedOriginalSiteHashes().isEmpty());
            assertEquals(1, scope.getR8MappedFieldProvenance());
            assertEquals(2, scope.getR8RemovedFieldProvenance());
            assertEquals(1, scope.getR8FallbackFieldProvenance());
        } finally {
            Files.deleteIfExists(usage);
            Files.deleteIfExists(mapping);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void validatesStringQualityGateConfiguration() {
        StringEncryptionExtension strings = new StringEncryptionExtension();
        DexCfgObfuscatorPlugin.validateStringQualityConfiguration(strings);

        strings.setMinEncryptedStrings(-1);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.validateStringQualityConfiguration(strings));
        strings.setMinEncryptedStrings(0);
        strings.setMinModifiedClasses(-1);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.validateStringQualityConfiguration(strings));
        strings.setMinModifiedClasses(0);
        strings.setMaxSkippedStrings(-1);
        assertThrows(GradleException.class,
                () -> DexCfgObfuscatorPlugin.validateStringQualityConfiguration(strings));
    }

    @Test
    public void cachedVerificationResetClearsDerivedGateDiagnostics() {
        ObfuscatorStats stats = new ObfuscatorStats();
        stats.stringPlaintextVerified = true;
        stats.stringPlaintextGateMode = "STRICT_WHOLE_POOL";
        stats.stringDexFilesScanned = 1;
        stats.stringPoolEntriesScanned = 2;
        stats.stringPlaintextHashesTracked = 3;
        stats.stringPlaintextLeaks = 4;
        stats.stringPlaintextLeakOccurrences = 5;
        stats.stringRuntimePlaintextLeaks = 6;
        stats.stringRuntimePlaintextLeakOccurrences = 7;
        stats.stringScopedRuntimePlaintextLeaks = 6;
        stats.stringScopedRuntimePlaintextLeakOccurrences = 7;
        stats.stringGlobalRuntimeFallbackHashesTracked = 8;
        stats.stringGlobalRuntimeFallbackPlaintextLeaks = 9;
        stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences = 10;
        stats.stringOwnerRuntimePlaintextCollisions = 14;
        stats.stringOwnerRuntimePlaintextCollisionOccurrences = 15;
        stats.stringGlobalRuntimePlaintextCollisions = 16;
        stats.stringGlobalRuntimePlaintextCollisionOccurrences = 17;
        stats.stringTargetClassesResolved = 18;
        stats.stringTargetClassesScanned = 19;
        stats.stringTargetMethodsResolved = 20;
        stats.stringTargetMethodsScanned = 21;
        stats.stringTargetFieldsResolved = 22;
        stats.stringTargetFieldsScanned = 23;
        stats.stringR8MappedMethodSites = 24;
        stats.stringR8RemovedMethodSites = 25;
        stats.stringR8IdentityMethodSites = 26;
        stats.stringR8FallbackMethodSites = 27;
        stats.stringR8MappedFieldProvenance = 28;
        stats.stringR8RemovedFieldProvenance = 29;
        stats.stringR8IdentityFieldProvenance = 30;
        stats.stringR8FallbackFieldProvenance = 31;
        stats.stringRemovedOriginalSiteHashesTracked = 32;
        stats.stringIdentityFieldProvenanceResolved = 33;
        stats.stringIdentityFieldProvenanceScanned = 34;
        stats.stringWholePoolPlaintextCollisions = 8;
        stats.stringWholePoolPlaintextCollisionOccurrences = 9;
        stats.stringConstStringReferencesScanned = 10;
        stats.stringStaticStringValuesScanned = 11;
        stats.stringAnnotationStringValuesScanned = 12;
        stats.stringCallSiteStringValuesScanned = 13;

        DexCfgObfuscatorPlugin.resetStringVerificationStats(stats, 23);

        assertFalse(stats.stringPlaintextVerified);
        assertEquals("DISABLED", stats.stringPlaintextGateMode);
        assertEquals(0, stats.stringDexFilesScanned);
        assertEquals(0, stats.stringPoolEntriesScanned);
        assertEquals(23, stats.stringPlaintextHashesTracked);
        assertEquals(0, stats.stringPlaintextLeaks);
        assertEquals(0, stats.stringPlaintextLeakOccurrences);
        assertEquals(0, stats.stringRuntimePlaintextLeaks);
        assertEquals(0, stats.stringRuntimePlaintextLeakOccurrences);
        assertEquals(0, stats.stringScopedRuntimePlaintextLeaks);
        assertEquals(0, stats.stringScopedRuntimePlaintextLeakOccurrences);
        assertEquals(0, stats.stringGlobalRuntimeFallbackHashesTracked);
        assertEquals(0, stats.stringGlobalRuntimeFallbackPlaintextLeaks);
        assertEquals(0, stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences);
        assertEquals(0, stats.stringOwnerRuntimePlaintextCollisions);
        assertEquals(0, stats.stringOwnerRuntimePlaintextCollisionOccurrences);
        assertEquals(0, stats.stringGlobalRuntimePlaintextCollisions);
        assertEquals(0, stats.stringGlobalRuntimePlaintextCollisionOccurrences);
        assertEquals(0, stats.stringTargetClassesResolved);
        assertEquals(0, stats.stringTargetClassesScanned);
        assertEquals(0, stats.stringTargetMethodsResolved);
        assertEquals(0, stats.stringTargetMethodsScanned);
        assertEquals(0, stats.stringTargetFieldsResolved);
        assertEquals(0, stats.stringTargetFieldsScanned);
        assertEquals(0, stats.stringR8MappedMethodSites);
        assertEquals(0, stats.stringR8RemovedMethodSites);
        assertEquals(0, stats.stringR8IdentityMethodSites);
        assertEquals(0, stats.stringR8FallbackMethodSites);
        assertEquals(0, stats.stringR8MappedFieldProvenance);
        assertEquals(0, stats.stringR8RemovedFieldProvenance);
        assertEquals(0, stats.stringR8IdentityFieldProvenance);
        assertEquals(0, stats.stringR8FallbackFieldProvenance);
        assertEquals(0, stats.stringRemovedOriginalSiteHashesTracked);
        assertEquals(0, stats.stringIdentityFieldProvenanceResolved);
        assertEquals(0, stats.stringIdentityFieldProvenanceScanned);
        assertEquals(0, stats.stringWholePoolPlaintextCollisions);
        assertEquals(0, stats.stringWholePoolPlaintextCollisionOccurrences);
        assertEquals(0, stats.stringConstStringReferencesScanned);
        assertEquals(0, stats.stringStaticStringValuesScanned);
        assertEquals(0, stats.stringAnnotationStringValuesScanned);
        assertEquals(0, stats.stringCallSiteStringValuesScanned);
    }

    @Test
    public void mapsLibraryRuntimeAndStrictVerificationIntoReportableStats() throws Exception {
        String metadataCollision = "LIBRARY_MEMBER_COLLISION_702431";
        String runtimePayload = "LIBRARY_RUNTIME_PAYLOAD_861205";
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL,
                "fixture/library/Stats", null, "java/lang/Object", null);
        MethodVisitor metadata = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                metadataCollision, "()V", null, null);
        metadata.visitCode();
        metadata.visitInsn(Opcodes.RETURN);
        metadata.visitMaxs(0, 0);
        metadata.visitEnd();
        MethodVisitor payload = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()Ljava/lang/String;", null, null);
        payload.visitCode();
        payload.visitLdcInsn(runtimePayload);
        payload.visitInsn(Opcodes.ARETURN);
        payload.visitMaxs(1, 0);
        payload.visitEnd();
        writer.visitEnd();
        File classFile = Files.createTempFile("library-stats-", ".class").toFile();
        try {
            Files.write(classFile.toPath(), writer.toByteArray());
            Set<String> hashes = new HashSet<>();
            hashes.add(StringPlaintextVerifier.sha256(metadataCollision));
            hashes.add(StringPlaintextVerifier.sha256(runtimePayload));

            ObfuscatorStats normal = new ObfuscatorStats();
            DexCfgObfuscatorPlugin.applyLibraryStringVerificationStats(
                    StringClassConstantPoolCompactor.verifyNoPlaintext(
                            Collections.singletonList(classFile), hashes), normal);
            assertEquals("LIBRARY_JVM_RUNTIME_PAYLOAD", normal.stringPlaintextGateMode);
            assertEquals(1, normal.stringPlaintextLeaks);
            assertEquals(1, normal.stringRuntimePlaintextLeaks);
            assertEquals(2, normal.stringWholePoolPlaintextCollisions);
            assertEquals(1, normal.stringConstStringReferencesScanned);

            ObfuscatorStats strict = new ObfuscatorStats();
            DexCfgObfuscatorPlugin.applyLibraryStringVerificationStats(
                    StringClassConstantPoolCompactor.verifyNoPlaintext(
                            Collections.singletonList(classFile), hashes, true), strict);
            assertEquals("LIBRARY_JVM_STRICT_WHOLE_POOL", strict.stringPlaintextGateMode);
            assertEquals(2, strict.stringPlaintextLeaks);
            assertEquals(1, strict.stringRuntimePlaintextLeaks);
            assertEquals(2, strict.stringWholePoolPlaintextCollisions);
        } finally {
            Files.deleteIfExists(classFile.toPath());
        }
    }

    @Test
    public void rejectsStrictWholeArtifactClaimForDynamicFeatures() {
        StringEncryptionExtension strings = new StringEncryptionExtension();
        assertThrows(GradleException.class, () ->
                DexCfgObfuscatorPlugin.validateDynamicFeatureCoverage(
                        java.util.Collections.singletonList(":feature"), strings));

        strings.setFailOnPlaintextLeak(false);
        DexCfgObfuscatorPlugin.validateDynamicFeatureCoverage(
                java.util.Collections.singletonList(":feature"), strings);
        DexCfgObfuscatorPlugin.validateDynamicFeatureCoverage(
                java.util.Collections.emptyList(), new StringEncryptionExtension());
    }

    @Test
    public void evidenceSourceNeverHidesAMissingEnabledStage() {
        assertEquals("MISSING", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                false, false, true));
        assertEquals("PARTIAL_MISSING", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                true, false, true));
        assertEquals("PARTIAL_MISSING", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                false, true, true));
        assertEquals("MIXED", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                true, true, false));
        assertEquals("CURRENT_BUILD", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                true, false, false));
        assertEquals("CACHED_VERIFIED", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                false, true, false));
        assertEquals("MISSING", DexCfgObfuscatorPlugin.combinedEvidenceSource(
                false, false, false));
    }

    public static final class ProtectionVariant {
        public final CapturingFiles proguardFiles = new CapturingFiles();
        public final CapturingFiles consumerProguardFiles = new CapturingFiles();

        public CapturingFiles getProguardFiles() {
            return proguardFiles;
        }

        public CapturingFiles getConsumerProguardFiles() {
            return consumerProguardFiles;
        }
    }

    public static final class CapturingFiles {
        public final java.util.List<Object> values = new java.util.ArrayList<>();

        public void add(Object value) {
            values.add(value);
        }
    }
}
