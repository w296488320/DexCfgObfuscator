package com.hunter.dexcfgobf.gradle;

import com.hunter.dexcfgobf.BuildEvidenceStore;
import com.hunter.dexcfgobf.ObfuscatorStats;
import com.hunter.dexcfgobf.string.StringEncryptionContext;
import com.hunter.dexcfgobf.string.StringEncryptionMode;
import com.hunter.dexcfgobf.string.StringEncryptionParameters;

import org.gradle.api.Project;
import org.gradle.api.GradleException;
import org.gradle.api.tasks.Input;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;

public class IncrementalStringEvidenceMergeTest {
    private static final String DIGEST = "string-digest";

    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void revisitedOwnerReplacesDeletedOrRenamedMembersWhileUnchangedOwnerSurvives()
            throws Exception {
        String oldHash = hash('a');
        String currentHash = hash('b');
        String unchangedHash = hash('c');
        File evidence = writeEvidence("changed-owner",
                set(oldHash, unchangedHash),
                mapOf(
                        "com.example.Changed", set(oldHash),
                        "com.example.Unchanged", set(unchangedHash)),
                mapOf(
                        "com/example/Changed->old()Ljava/lang/String;", set(oldHash),
                        "com/example/Changed-><clinit>()V", set(oldHash),
                        "com/example/Unchanged->keep()Ljava/lang/String;", set(unchangedHash)),
                mapOf("com/example/Changed->SECRET", set(oldHash)));

        DexCfgObfuscatorPlugin.StringEvidenceScope merged = merge(project(false), evidence,
                set(currentHash), set("com.example.Changed"),
                set("com.example.Changed", "com.example.Unchanged"),
                mapOf("com.example.Changed", set(currentHash)),
                mapOf("com/example/Changed->renamed(I)Ljava/lang/String;", set(currentHash)),
                Collections.emptyMap());

        assertEquals(set(currentHash, unchangedHash), merged.getPlaintextHashes());
        assertEquals(set(currentHash),
                merged.getPlaintextHashesByOriginalClass().get("com.example.Changed"));
        assertEquals(set(unchangedHash),
                merged.getPlaintextHashesByOriginalClass().get("com.example.Unchanged"));
        assertTrue(merged.getPlaintextHashesByOriginalMethod().containsKey(
                "com/example/Changed->renamed(I)Ljava/lang/String;"));
        assertTrue(merged.getPlaintextHashesByOriginalMethod().containsKey(
                "com/example/Unchanged->keep()Ljava/lang/String;"));
        assertFalse(merged.getPlaintextHashesByOriginalMethod().containsKey(
                "com/example/Changed->old()Ljava/lang/String;"));
        assertFalse(merged.getPlaintextHashesByOriginalMethod().containsKey(
                "com/example/Changed-><clinit>()V"));
        assertFalse(merged.getPlaintextHashesByOriginalField().containsKey(
                "com/example/Changed->SECRET"));
    }

    @Test
    public void revisitedOwnerWithNoCurrentStringsClearsEveryPriorScope() throws Exception {
        String priorHash = hash('d');
        File evidence = writeEvidence("zero-strings", set(priorHash),
                mapOf("com.example.Zero", set(priorHash)),
                mapOf("com/example/Zero->secret()Ljava/lang/String;", set(priorHash)),
                Collections.emptyMap());

        DexCfgObfuscatorPlugin.StringEvidenceScope merged = merge(project(false), evidence,
                Collections.emptySet(), set("com.example.Zero"), set("com.example.Zero"),
                Collections.emptyMap(),
                Collections.emptyMap(), Collections.emptyMap());

        assertTrue(merged.getPlaintextHashes().isEmpty());
        assertTrue(merged.getPlaintextHashesByOriginalClass().isEmpty());
        assertTrue(merged.getPlaintextHashesByOriginalMethod().isEmpty());
        assertTrue(merged.getPlaintextHashesByOriginalField().isEmpty());
    }

    @Test
    public void sharedHashSurvivesWhenAnUnvisitedOwnerStillUsesIt() throws Exception {
        String sharedHash = hash('e');
        File evidence = writeEvidence("shared-hash", set(sharedHash),
                mapOf(
                        "com.example.Changed", set(sharedHash),
                        "com.example.Unchanged", set(sharedHash)),
                mapOf(
                        "com/example/Changed->old()Ljava/lang/String;", set(sharedHash),
                        "com/example/Unchanged->keep()Ljava/lang/String;", set(sharedHash)),
                Collections.emptyMap());

        DexCfgObfuscatorPlugin.StringEvidenceScope merged = merge(project(false), evidence,
                Collections.emptySet(), set("com/example/Changed"),
                set("com/example/Changed", "com/example/Unchanged"), Collections.emptyMap(),
                Collections.emptyMap(), Collections.emptyMap());

        assertEquals(set(sharedHash), merged.getPlaintextHashes());
        assertFalse(merged.getPlaintextHashesByOriginalClass().containsKey(
                "com.example.Changed"));
        assertEquals(set(sharedHash),
                merged.getPlaintextHashesByOriginalClass().get("com.example.Unchanged"));
        assertFalse(merged.getPlaintextHashesByOriginalMethod().containsKey(
                "com/example/Changed->old()Ljava/lang/String;"));
        assertTrue(merged.getPlaintextHashesByOriginalMethod().containsKey(
                "com/example/Unchanged->keep()Ljava/lang/String;"));
    }

    @Test
    public void ownerAbsentFromCurrentScopedInventoryIsSafelyDroppedAsDeleted()
            throws Exception {
        String deletedHash = hash('4');
        File evidence = writeEvidence("possibly-deleted-owner", set(deletedHash),
                mapOf("com.example.PossiblyDeleted", set(deletedHash)),
                mapOf("com/example/PossiblyDeleted->value()Ljava/lang/String;", set(deletedHash)),
                Collections.emptyMap());

        DexCfgObfuscatorPlugin.StringEvidenceScope merged = merge(project(false), evidence,
                Collections.emptySet(), Collections.emptySet(), Collections.emptySet(),
                Collections.emptyMap(),
                Collections.emptyMap(), Collections.emptyMap());

        assertTrue(merged.getPlaintextHashes().isEmpty());
        assertTrue(merged.getPlaintextHashesByOriginalClass().isEmpty());
        assertTrue(merged.getPlaintextHashesByOriginalMethod().isEmpty());
    }

    @Test
    public void zeroVisitPureDeletionDoesNotReusePriorQualityCounters() throws Exception {
        String deletedHash = hash('5');
        File evidence = writeEvidence("zero-visit-pure-deletion", set(deletedHash),
                mapOf("com.example.Deleted", set(deletedHash)),
                mapOf("com/example/Deleted->value()Ljava/lang/String;", set(deletedHash)),
                Collections.emptyMap());
        Project fullRerun = project(true);
        DexCfgObfuscatorPlugin.StringEvidenceScope reconciled = merge(fullRerun, evidence,
                Collections.emptySet(), Collections.emptySet(), Collections.emptySet(),
                Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());
        ObfuscatorStats stalePriorStats = new ObfuscatorStats();
        stalePriorStats.stringConstantsEncrypted = 91;
        stalePriorStats.stringClassesModified = 17;
        stalePriorStats.stringConstantsSkipped = 13;
        stalePriorStats.stringSkippedWhitespace = 2;
        stalePriorStats.stringSkippedTooLarge = 3;
        stalePriorStats.stringSkippedInvalidUnicode = 4;
        stalePriorStats.stringSkippedFiltered = 5;
        stalePriorStats.stringUnsupportedConstants = 6;
        stalePriorStats.stringIdentityCiphertexts = 7;

        applyReconciledStats(stalePriorStats, reconciled, fullRerun);

        assertEquals(0, stalePriorStats.stringConstantsEncrypted);
        assertEquals(0, stalePriorStats.stringClassesModified);
        assertEquals(0, stalePriorStats.stringClassesVisited);
        assertEquals(0, stalePriorStats.stringConstantsSkipped);
        assertEquals(0, stalePriorStats.stringSkippedWhitespace);
        assertEquals(0, stalePriorStats.stringSkippedTooLarge);
        assertEquals(0, stalePriorStats.stringSkippedInvalidUnicode);
        assertEquals(0, stalePriorStats.stringSkippedFiltered);
        assertEquals(0, stalePriorStats.stringUnsupportedConstants);
        assertEquals(0, stalePriorStats.stringIdentityCiphertexts);
        assertEquals("FULL", stalePriorStats.stringCoverageStatus);
    }

    @Test
    public void zeroVisitExcludedOnlyChangeKeepsActiveScopeAsPartial() throws Exception {
        String retainedHash = hash('6');
        File evidence = writeEvidence("zero-visit-excluded-change", set(retainedHash),
                mapOf("com.example.Retained", set(retainedHash)),
                mapOf("com/example/Retained->value()Ljava/lang/String;", set(retainedHash)),
                Collections.emptyMap());
        Project incremental = project(false);
        DexCfgObfuscatorPlugin.StringEvidenceScope reconciled = merge(incremental, evidence,
                Collections.emptySet(), Collections.emptySet(), set("com.example.Retained"),
                Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());
        ObfuscatorStats stalePriorStats = new ObfuscatorStats();
        stalePriorStats.stringConstantsEncrypted = 91;
        stalePriorStats.stringClassesModified = 17;
        stalePriorStats.stringConstantsSkipped = 8;
        stalePriorStats.stringSkippedTooLarge = 3;

        applyReconciledStats(stalePriorStats, reconciled, incremental);

        assertEquals(1, stalePriorStats.stringConstantsEncrypted);
        assertEquals(1, stalePriorStats.stringClassesModified);
        assertEquals(0, stalePriorStats.stringClassesVisited);
        assertEquals(8, stalePriorStats.stringConstantsSkipped);
        assertEquals(3, stalePriorStats.stringSkippedTooLarge);
        assertEquals("PARTIAL_OR_FULL", stalePriorStats.stringCoverageStatus);
    }

    @Test
    public void zeroVisitFingerprintMismatchRequiresAsmTransformToRun() throws Exception {
        Project project = project(false);
        project.getTasks().create("transformDebugClassesWithAsm");

        GradleException failure = assertThrows(GradleException.class,
                () -> requireExecutedTransform(project));

        assertTrue(failure.getMessage().contains("no current string visits"));
        assertTrue(failure.getMessage().contains("run clean with --rerun-tasks"));
    }

    @Test
    public void currentHashWithoutExactOwnerScopeFailsWithoutLoggingTheHash() throws Exception {
        String priorHash = hash('f');
        String boundaryHash = hash('1');
        File evidence = writeEvidence("boundary-hash", set(priorHash),
                mapOf("com.example.Prior", set(priorHash)),
                mapOf("com/example/Prior->keep()Ljava/lang/String;", set(priorHash)),
                Collections.emptyMap());

        GradleException failure = assertThrows(GradleException.class,
                () -> merge(project(false), evidence, set(boundaryHash), Collections.emptySet(),
                        set("com.example.Prior"), Collections.emptyMap(),
                        Collections.emptyMap(), Collections.emptyMap()));

        assertTrue(failure.getMessage().contains("not exactly owner-scoped"));
        assertTrue(failure.getMessage().contains("hashes are not logged"));
        assertFalse(failure.getMessage().contains(boundaryHash));
    }

    @Test
    public void fullRerunUsesOnlyCurrentScopeAndNeverCarriesPriorEvidence() throws Exception {
        String priorHash = hash('2');
        String currentHash = hash('3');
        File evidence = writeEvidence("full-rerun", set(priorHash),
                mapOf("com.example.Prior", set(priorHash)),
                mapOf("com/example/Prior->old()Ljava/lang/String;", set(priorHash)),
                Collections.emptyMap());

        DexCfgObfuscatorPlugin.StringEvidenceScope merged = merge(project(true), evidence,
                set(currentHash), set("com.example.Current"),
                set("com.example.Current"),
                mapOf("com.example.Current", set(currentHash)),
                mapOf("com/example/Current->value()Ljava/lang/String;", set(currentHash)),
                Collections.emptyMap());

        assertEquals(set(currentHash), merged.getPlaintextHashes());
        assertEquals(Collections.singleton("com.example.Current"),
                merged.getPlaintextHashesByOriginalClass().keySet());
        assertEquals(Collections.singleton("com/example/Current->value()Ljava/lang/String;"),
                merged.getPlaintextHashesByOriginalMethod().keySet());
    }

    @Test
    public void strictCoverageForcesUniqueAsmInputsWithoutCommandLineRerun() {
        Project ordinary = project(false);
        assertEquals("cacheable",
                DexCfgObfuscatorPlugin.fullCoverageInvocationNonce(ordinary, false));

        String first = DexCfgObfuscatorPlugin.fullCoverageInvocationNonce(ordinary, true);
        String second = DexCfgObfuscatorPlugin.fullCoverageInvocationNonce(ordinary, true);
        assertNotEquals("cacheable", first);
        assertNotEquals(first, second);
        assertTrue(DexCfgObfuscatorPlugin.isFullStringCoverageInvocation(ordinary, true));

        Project explicitRerun = project(true);
        assertNotEquals("cacheable",
                DexCfgObfuscatorPlugin.fullCoverageInvocationNonce(explicitRerun, false));
        assertTrue(DexCfgObfuscatorPlugin.isFullStringCoverageInvocation(
                explicitRerun, false));
    }

    @Test
    public void fullCoverageNonceRemainsAGradleInput() throws Exception {
        Method getter = StringEncryptionParameters.class.getMethod(
                "getFullCoverageInvocationNonce");

        assertTrue(getter.isAnnotationPresent(Input.class));
    }

    @Test
    public void cachedApplicationCoverageCannotStayFullWithDynamicFeatures() {
        Project baseOnly = project(false);
        assertEquals("CACHED_FULL",
                DexCfgObfuscatorPlugin.restoredApplicationStringCoverageStatus(
                        baseOnly, "FULL"));

        Project withFeature = project(false);
        withFeature.getExtensions().add("android",
                new AndroidFeatures(Collections.singleton(":feature")));
        assertEquals("CACHED_PARTIAL",
                DexCfgObfuscatorPlugin.restoredApplicationStringCoverageStatus(
                        withFeature, "FULL"));
        assertEquals("CACHED_PARTIAL",
                DexCfgObfuscatorPlugin.restoredApplicationStringCoverageStatus(
                        withFeature, "CACHED_FULL"));
    }

    @Test
    public void scopedInventoryProvesEverySelectedOwnerWasVisited() {
        StringEncryptionContext context = StringEncryptionContext.create(
                null, null, null, Collections.singletonList("fixture"),
                Collections.singletonList("fixture.excluded"), "fixture.RuntimeBridge",
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false);
        Set<String> active = set("fixture/Feature", "fixture/SecondFeature",
                "fixture/excluded/Ignored", "fixture/R$string", "other/Dependency");

        assertTrue(DexCfgObfuscatorPlugin.hasCompleteVisitedStringCoverage(
                context, active, set("fixture.Feature", "fixture.SecondFeature")));
        assertFalse(DexCfgObfuscatorPlugin.hasCompleteVisitedStringCoverage(
                context, active, set("fixture.Feature")));
        assertFalse(DexCfgObfuscatorPlugin.hasCompleteVisitedStringCoverage(
                context, active,
                set("fixture.Feature", "fixture.SecondFeature", "other.Dependency")));
    }

    @Test
    public void forcedFullCoverageUsesOnlyCurrentScopeWithoutRerunFlag() throws Exception {
        String priorHash = hash('7');
        String currentHash = hash('8');
        File evidence = writeEvidence("forced-full", set(priorHash),
                mapOf("com.example.Prior", set(priorHash)),
                mapOf("com/example/Prior->old()Ljava/lang/String;", set(priorHash)),
                Collections.emptyMap());

        DexCfgObfuscatorPlugin.StringEvidenceScope merged = merge(project(false), evidence,
                set(currentHash), set("com.example.Current"), set("com.example.Current"),
                mapOf("com.example.Current", set(currentHash)),
                mapOf("com/example/Current->value()Ljava/lang/String;", set(currentHash)),
                Collections.emptyMap(), true);

        assertEquals(set(currentHash), merged.getPlaintextHashes());
        assertEquals(Collections.singleton("com.example.Current"),
                merged.getPlaintextHashesByOriginalClass().keySet());
    }

    private File writeEvidence(String name,
                               Set<String> hashes,
                               Map<String, Set<String>> byClass,
                               Map<String, Set<String>> byMethod,
                               Map<String, Set<String>> byField) throws Exception {
        File evidence = new File(temporary.newFolder(name), "string.evidence");
        ObfuscatorStats stats = new ObfuscatorStats();
        stats.stringCoverageStatus = "FULL";
        BuildEvidenceStore.writeString(evidence, "prior-audit", DIGEST, stats,
                hashes, byClass, byMethod, byField);
        return evidence;
    }

    private static Project project(boolean fullRerun) {
        Project project = ProjectBuilder.builder().withName(
                fullRerun ? "full-rerun" : "incremental").build();
        project.getGradle().getStartParameter().setRerunTasks(fullRerun);
        return project;
    }

    public static final class AndroidFeatures {
        private final Set<String> dynamicFeatures;

        AndroidFeatures(Set<String> dynamicFeatures) {
            this.dynamicFeatures = dynamicFeatures;
        }

        public Set<String> getDynamicFeatures() {
            return dynamicFeatures;
        }
    }

    private static DexCfgObfuscatorPlugin.StringEvidenceScope merge(
            Project project,
            File evidence,
            Set<String> currentHashes,
            Set<String> visitedOwners,
            Set<String> activeOwners,
            Map<String, Set<String>> currentClasses,
            Map<String, Set<String>> currentMethods,
            Map<String, Set<String>> currentFields) throws Exception {
        return merge(project, evidence, currentHashes, visitedOwners, activeOwners,
                currentClasses, currentMethods, currentFields, null);
    }

    private static DexCfgObfuscatorPlugin.StringEvidenceScope merge(
            Project project,
            File evidence,
            Set<String> currentHashes,
            Set<String> visitedOwners,
            Set<String> activeOwners,
            Map<String, Set<String>> currentClasses,
            Map<String, Set<String>> currentMethods,
            Map<String, Set<String>> currentFields,
            Boolean fullCurrentCoverage) throws Exception {
        Class<?>[] parameterTypes = fullCurrentCoverage == null
                ? new Class<?>[]{Project.class, File.class, String.class, Set.class, Set.class,
                        Set.class, Map.class, Map.class, Map.class, int.class, int.class,
                        String.class, String.class}
                : new Class<?>[]{Project.class, File.class, String.class, Set.class, Set.class,
                        Set.class, Map.class, Map.class, Map.class, int.class, int.class,
                        String.class, String.class, boolean.class};
        Method method = DexCfgObfuscatorPlugin.class.getDeclaredMethod(
                "mergePriorStringEvidence", parameterTypes);
        method.setAccessible(true);
        try {
            Object[] arguments = fullCurrentCoverage == null
                    ? new Object[]{project, evidence, DIGEST, currentHashes, visitedOwners,
                            activeOwners, currentClasses, currentMethods, currentFields, 0, 0,
                            "debug", "application DEX"}
                    : new Object[]{project, evidence, DIGEST, currentHashes, visitedOwners,
                            activeOwners, currentClasses, currentMethods, currentFields, 0, 0,
                            "debug", "application DEX", fullCurrentCoverage};
            return (DexCfgObfuscatorPlugin.StringEvidenceScope) method.invoke(null, arguments);
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw failure;
        }
    }

    private static void applyReconciledStats(
            ObfuscatorStats stats,
            DexCfgObfuscatorPlugin.StringEvidenceScope scope,
            Project project) throws Exception {
        Method method = DexCfgObfuscatorPlugin.class.getDeclaredMethod(
                "applyReconciledStringScopeStats", ObfuscatorStats.class,
                DexCfgObfuscatorPlugin.StringEvidenceScope.class, Project.class);
        invokePrivate(method, stats, scope, project);
    }

    private static void requireExecutedTransform(Project project) throws Exception {
        Method method = DexCfgObfuscatorPlugin.class.getDeclaredMethod(
                "requireExecutedAsmTransformForZeroVisitReconciliation",
                Project.class, String.class, String.class);
        invokePrivate(method, project, "Debug", "debug");
    }

    private static Object invokePrivate(Method method, Object... arguments) throws Exception {
        method.setAccessible(true);
        try {
            return method.invoke(null, arguments);
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw failure;
        }
    }

    @SafeVarargs
    private static <T> Set<T> set(T... values) {
        return new LinkedHashSet<>(Arrays.asList(values));
    }

    private static <K, V> Map<K, V> mapOf(Object... alternatingKeysAndValues) {
        Map<K, V> result = new LinkedHashMap<>();
        for (int index = 0; index < alternatingKeysAndValues.length; index += 2) {
            @SuppressWarnings("unchecked") K key = (K) alternatingKeysAndValues[index];
            @SuppressWarnings("unchecked") V value = (V) alternatingKeysAndValues[index + 1];
            result.put(key, value);
        }
        return result;
    }

    private static String hash(char value) {
        char[] chars = new char[64];
        Arrays.fill(chars, value);
        return new String(chars);
    }
}
