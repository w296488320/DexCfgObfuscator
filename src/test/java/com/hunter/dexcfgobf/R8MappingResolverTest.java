package com.hunter.dexcfgobf;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public final class R8MappingResolverTest {

    @Test
    public void resolvesOnlyExactOriginalOwnersAndReportsMissingOwners() throws Exception {
        Path mapping = writeMapping(
                "# compiler: R8",
                "com.example.Target -> final.pkg.a:",
                "    1:1:void run():1:1 -> a",
                "com.example.TargetExtra -> final.pkg.b:",
                "com.example.Identity -> com.example.Identity:");
        try {
            ArrayList<String> requested = new ArrayList<>(Arrays.asList(
                    "Lcom/example/Target;",
                    "com.example.Target", // 规范化后重复，只计一个请求。
                    "com/example/Missing"));

            R8MappingResolver.ExactOwnerResolution result =
                    R8MappingResolver.resolveExactOwners(mapping.toFile(), requested);
            requested.clear(); // 返回值不得持有调用方 collection 的可变引用。

            assertEquals(2, result.getRequestedCount());
            assertEquals(1, result.getResolvedCount());
            assertEquals(1, result.getMissingCount());
            assertEquals(Collections.singletonMap("com/example/Target", "final/pkg/a"),
                    result.getResolvedOwners());
            assertEquals(Collections.singleton("com/example/Missing"), result.getMissingOwners());
            assertFalse(result.getResolvedOwners().containsKey("com/example/TargetExtra"));
            assertEquals(Arrays.asList("com/example/Target", "com/example/Missing"),
                    new ArrayList<>(result.getRequestedOwners()));
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void resultCollectionsAreDefensivelyImmutable() throws Exception {
        Path mapping = writeMapping("com.example.Target -> a:");
        try {
            R8MappingResolver.ExactOwnerResolution result =
                    R8MappingResolver.resolveExactOwners(mapping.toFile(),
                            Arrays.asList("com.example.Target", "com.example.Missing"));

            assertThrows(UnsupportedOperationException.class,
                    () -> result.getRequestedOwners().add("other/Owner"));
            assertThrows(UnsupportedOperationException.class,
                    () -> result.getResolvedOwners().put("other/Owner", "b"));
            assertThrows(UnsupportedOperationException.class,
                    () -> result.getMissingOwners().clear());
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void acceptsIdempotentDuplicateButRejectsConflictingDuplicate() throws Exception {
        Path same = writeMapping(
                "com.example.Target -> a:",
                "com/example/Target -> a:");
        try {
            R8MappingResolver.ExactOwnerResolution result =
                    R8MappingResolver.resolveExactOwners(same.toFile(),
                            Collections.singleton("com.example.Target"));
            assertEquals(Collections.singletonMap("com/example/Target", "a"),
                    result.getResolvedOwners());
        } finally {
            Files.deleteIfExists(same);
        }

        Path conflicting = writeMapping(
                "com.example.Target -> a:",
                "com/example/Target -> b:");
        try {
            IOException failure = assertThrows(IOException.class,
                    () -> R8MappingResolver.resolveExactOwners(conflicting.toFile(),
                            Collections.singleton("com.example.Target")));
            assertTrue(failure.getMessage().contains("Conflicting R8 class mappings"));
            assertTrue(failure.getMessage().contains(":2"));
        } finally {
            Files.deleteIfExists(conflicting);
        }
    }

    @Test
    public void rejectsMalformedTopLevelClassMappingLines() throws Exception {
        for (String invalid : Arrays.asList(
                "com.example.MissingColon -> a",
                "com.example.EmptyTarget -> :",
                "com.example.Bad -> bad:name:",
                "not a mapping line")) {
            Path mapping = writeMapping(invalid);
            try {
                IOException failure = assertThrows(IOException.class,
                        () -> R8MappingResolver.resolveExactOwners(mapping.toFile(),
                                Collections.singleton("com.example.Target")));
                assertTrue(failure.getMessage().contains("Invalid R8 class mapping"));
                assertTrue(failure.getMessage().contains(":1"));
            } finally {
                Files.deleteIfExists(mapping);
            }
        }
    }

    @Test
    public void applyDoesNotPartiallyMutateConfigWhenMappingIsInvalid() throws Exception {
        Path mapping = writeMapping(
                "com.example.First -> a:",
                "invalid top-level line");
        try {
            ObfuscatorConfig config = new ObfuscatorConfig();
            config.includePrefixes.add("com/example");
            config.resolvedIncludeClasses.add("existing/Owner");
            config.requireResolvedIncludeClasses = false;

            assertThrows(IOException.class,
                    () -> R8MappingResolver.apply(mapping.toFile(), config));
            assertEquals(Collections.singleton("existing/Owner"), config.resolvedIncludeClasses);
            assertFalse(config.requireResolvedIncludeClasses);
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void rejectsInvalidRequestedOwnerBeforeReturningAResult() throws Exception {
        Path mapping = writeMapping("com.example.Target -> a:");
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> R8MappingResolver.resolveExactOwners(mapping.toFile(),
                            Collections.singleton("com.example.Bad Owner")));
            assertThrows(IllegalArgumentException.class,
                    () -> R8MappingResolver.resolveExactOwners(mapping.toFile(),
                            Collections.singleton(null)));
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void resolvesQualifiedMovedMembersUnderTheirContainingFinalOwner() throws Exception {
        Path mapping = writeMapping(
                "com.example.platform.RuntimeProbe -> obfuscated.a:",
                "    int state -> a",
                "    2:5:java.lang.String com.example.crypto.RuntimeStringBridge.decrypt(java.lang.String,java.lang.String):21:21 -> q",
                "    6:9:java.lang.String com.example.crypto.RuntimeStringBridge.decrypt(java.lang.String,java.lang.String):22 -> q",
                "    3:5:java.lang.String com.example.crypto.RuntimeStringBridge.decrypt(byte[],byte[]):6:6 -> r",
                "    void <init>(java.lang.String) -> <init>",
                "    void work(int) -> s",
                "    10:12:void work(java.lang.String):30:31 -> t",
                "    byte[] com.example.crypto.RuntimeStringBridge.cache -> u");
        try {
            String decryptText = "com/example/crypto/RuntimeStringBridge"
                    + "->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
            String decryptBytes = "com/example/crypto/RuntimeStringBridge"
                    + "->decrypt([B[B)Ljava/lang/String;";
            String constructor = "com/example/platform/RuntimeProbe"
                    + "-><init>(Ljava/lang/String;)V";
            String overloadInt = "com/example/platform/RuntimeProbe->work(I)V";
            String overloadString = "com/example/platform/RuntimeProbe"
                    + "->work(Ljava/lang/String;)V";
            String missing = "com/example/crypto/RuntimeStringBridge->missing()V";
            String field = "com/example/crypto/RuntimeStringBridge->cache";

            R8MappingResolver.ExactMemberResolution result =
                    R8MappingResolver.resolveExactMembers(mapping.toFile(),
                            Arrays.asList(decryptText, decryptBytes, constructor,
                                    overloadInt, overloadString, missing),
                            Collections.singleton(field));

            assertEquals(7, result.getRequestedCount());
            assertEquals(6, result.getResolvedCount());
            assertEquals(1, result.getMissingCount());
            assertEquals(0, result.getConflictCount());
            assertEquals(5, result.getResolvedMethodCount());
            assertEquals(1, result.getResolvedFieldCount());
            assertEquals(Collections.singleton(missing), result.getMissingMethods());
            assertTrue(result.getMissingFields().isEmpty());
            assertFalse(result.isComplete());

            assertFinalMember(singleTarget(result.getResolvedMethods().get(decryptText)),
                    "obfuscated/a", "q");
            assertFinalMember(singleTarget(result.getResolvedMethods().get(decryptBytes)),
                    "obfuscated/a", "r");
            assertFinalMember(singleTarget(result.getResolvedMethods().get(constructor)),
                    "obfuscated/a", "<init>");
            assertFinalMember(singleTarget(result.getResolvedMethods().get(overloadInt)),
                    "obfuscated/a", "s");
            assertFinalMember(singleTarget(result.getResolvedMethods().get(overloadString)),
                    "obfuscated/a", "t");
            assertFinalMember(singleTarget(result.getResolvedFields().get(field)),
                    "obfuscated/a", "u");
            assertEquals(Collections.singleton("obfuscated/a"),
                    result.getResolvedFinalOwners());

            assertThrows(UnsupportedOperationException.class,
                    () -> result.getResolvedMethods().clear());
            assertThrows(UnsupportedOperationException.class,
                    () -> result.getResolvedFinalOwners().add("other/Owner"));

            ObfuscatorConfig config = new ObfuscatorConfig();
            config.includePrefixes.add("com/example/crypto");
            assertEquals(1, R8MappingResolver.apply(mapping.toFile(), config));
            assertEquals(Collections.singleton("obfuscated/a"),
                    config.resolvedIncludeClasses);
            assertTrue(config.resolvedClassWideIncludeClasses.isEmpty());
            assertEquals(new java.util.LinkedHashSet<>(Arrays.asList(
                    "obfuscated/a->q", "obfuscated/a->r")),
                    config.resolvedIncludeMethods);
            assertTrue(config.shouldProcessClass("Lobfuscated/a;"));
            assertTrue(config.shouldProcessMethod("Lobfuscated/a;", "q"));
            assertFalse(config.shouldProcessMethod("Lobfuscated/a;", "a"));
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void preservesEveryLegitimateInlineTargetForOneOriginalMember() throws Exception {
        Path mapping = writeMapping(
                "container.One -> a:",
                "    1:1:void source.Bridge.run(int):10:10 -> x",
                "    int source.Bridge.value -> f",
                "container.Two -> b:",
                "    2:2:void source.Bridge.run(int):20:20 -> y",
                "    int source.Bridge.value -> g");
        try {
            String method = "source/Bridge->run(I)V";
            String field = "source/Bridge->value";
            R8MappingResolver.ExactMemberResolution result =
                    R8MappingResolver.resolveExactMembers(mapping.toFile(),
                            Collections.singleton(method), Collections.singleton(field));

            assertEquals(2, result.getRequestedCount());
            assertEquals(2, result.getResolvedCount());
            assertEquals(0, result.getMissingCount());
            assertEquals(0, result.getConflictCount());
            assertEquals(4, result.getResolvedTargetCount());
            assertEquals(2, result.getResolvedMethods().get(method).size());
            assertEquals(2, result.getResolvedFields().get(field).size());
            assertTrue(result.isComplete());
            assertThrows(UnsupportedOperationException.class,
                    () -> result.getResolvedMethods().get(method).clear());
        } finally {
            Files.deleteIfExists(mapping);
        }
    }

    @Test
    public void rejectsInvalidMemberMappingsAndRequestedDescriptors() throws Exception {
        Path withoutHeader = writeMapping("    void run() -> a");
        try {
            assertThrows(IOException.class,
                    () -> R8MappingResolver.resolveExactMembers(withoutHeader.toFile(),
                            Collections.emptySet(), Collections.emptySet()));
        } finally {
            Files.deleteIfExists(withoutHeader);
        }

        Path invalidMember = writeMapping(
                "source.Owner -> a:",
                "    1:x:void run() -> b");
        try {
            IOException failure = assertThrows(IOException.class,
                    () -> R8MappingResolver.resolveExactMembers(invalidMember.toFile(),
                            Collections.emptySet(), Collections.emptySet()));
            assertTrue(failure.getMessage().contains("Invalid R8 member mapping"));
            assertTrue(failure.getMessage().contains(":2"));
        } finally {
            Files.deleteIfExists(invalidMember);
        }

        Path valid = writeMapping("source.Owner -> a:");
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> R8MappingResolver.resolveExactMembers(valid.toFile(),
                            Collections.singleton("source/Owner->run(Ljava.lang.String;)V"),
                            Collections.emptySet()));
            assertThrows(IllegalArgumentException.class,
                    () -> R8MappingResolver.resolveExactMembers(valid.toFile(),
                            Collections.singleton("source/Owner->run([V)V"),
                            Collections.emptySet()));
            assertThrows(IllegalArgumentException.class,
                    () -> R8MappingResolver.resolveExactMembers(valid.toFile(),
                            Collections.emptySet(),
                            Collections.singleton("source/Owner->bad:name")));
        } finally {
            Files.deleteIfExists(valid);
        }
    }

    @Test
    public void readsExactUsageAndSeedCompanionsWithoutTreatingClassHeadersAsRemoval()
            throws Exception {
        Path directory = Files.createTempDirectory("dex-cfg-obf-r8-companions-");
        Path mapping = directory.resolve("mapping.txt");
        Path usage = directory.resolve("usage.txt");
        Path seeds = directory.resolve("seeds.txt");
        String wholeMethod = "source/Whole->gone()V";
        String exactMethod = "source/Partial->gone(Ljava/lang/String;)Ljava/lang/String;";
        String identityMethod = "source/Partial->identity(I)V";
        String removedField = "source/Partial->DEAD";
        String identityField = "source/Partial->IDENTITY";
        try {
            Files.write(mapping, Arrays.asList(
                    "source.Whole -> R8$$REMOVED$$CLASS$$1:",
                    "source.Partial -> a:"), StandardCharsets.UTF_8);
            Files.write(usage, Arrays.asList(
                    "source.Whole",
                    "source.Partial:",
                    "    public final java.lang.String gone(java.lang.String)",
                    "    private static final java.lang.String DEAD"),
                    StandardCharsets.UTF_8);
            Files.write(seeds, Arrays.asList(
                    "source.Partial",
                    "source.Partial: void identity(int)",
                    "source.Partial: java.lang.String IDENTITY"),
                    StandardCharsets.UTF_8);

            R8MappingResolver.ShrinkerCompanionReports reports =
                    R8MappingResolver.readCompanionReports(mapping.toFile(),
                            Arrays.asList(wholeMethod, exactMethod, identityMethod),
                            Arrays.asList(removedField, identityField));

            assertTrue(reports.isUsageAvailable());
            assertTrue(reports.isSeedsAvailable());
            assertTrue(reports.isClassRemoved("source/Whole"));
            assertFalse(reports.isClassRemoved("source/Partial"));
            assertTrue(reports.isMethodRemoved(wholeMethod));
            assertTrue(reports.isMethodRemoved(exactMethod));
            assertFalse(reports.isMethodRemoved(identityMethod));
            assertTrue(reports.isFieldRemoved(removedField));
            assertFalse(reports.isFieldRemoved(identityField));
            assertTrue(reports.isMethodSeeded(identityMethod));
            assertEquals(Collections.singleton("Ljava/lang/String;"),
                    reports.getSeededFieldDescriptors(identityField));
            assertTrue(reports.isClassSeeded("source/Partial"));
        } finally {
            Files.deleteIfExists(seeds);
            Files.deleteIfExists(usage);
            Files.deleteIfExists(mapping);
            Files.deleteIfExists(directory);
        }
    }

    @Test
    public void missingOrMalformedCompanionsNeverBecomeRemovalOrIdentityProof()
            throws Exception {
        Path directory = Files.createTempDirectory("dex-cfg-obf-r8-companion-fallback-");
        Path mapping = directory.resolve("mapping.txt");
        String method = "source/Owner->work()V";
        String field = "source/Owner->VALUE";
        try {
            Files.write(mapping, Collections.singleton("source.Owner -> a:"),
                    StandardCharsets.UTF_8);
            R8MappingResolver.ShrinkerCompanionReports missing =
                    R8MappingResolver.readCompanionReports(mapping.toFile(),
                            Collections.singleton(method), Collections.singleton(field));
            assertFalse(missing.isUsageAvailable());
            assertFalse(missing.isSeedsAvailable());
            assertFalse(missing.isMethodRemoved(method));
            assertFalse(missing.isMethodSeeded(method));
            assertTrue(missing.getSeededFieldDescriptors(field).isEmpty());

            Files.write(directory.resolve("usage.txt"), Arrays.asList(
                    "source.Owner:",
                    "    this is not a member signature"), StandardCharsets.UTF_8);
            Files.write(directory.resolve("seeds.txt"), Arrays.asList(
                    "source.Owner: broken(",
                    "source.Owner: int VALUE"), StandardCharsets.UTF_8);
            R8MappingResolver.ShrinkerCompanionReports malformed =
                    R8MappingResolver.readCompanionReports(mapping.toFile(),
                            Collections.singleton(method), Collections.singleton(field));
            assertTrue(malformed.isUsageAvailable());
            assertTrue(malformed.isSeedsAvailable());
            assertFalse(malformed.isMethodRemoved(method));
            assertFalse(malformed.isMethodSeeded(method));
            // A same-name non-String field is not exact provenance for transformed String data.
            assertTrue(malformed.getSeededFieldDescriptors(field).isEmpty());
        } finally {
            Files.deleteIfExists(directory.resolve("seeds.txt"));
            Files.deleteIfExists(directory.resolve("usage.txt"));
            Files.deleteIfExists(mapping);
            Files.deleteIfExists(directory);
        }
    }

    private static void assertFinalMember(
            R8MappingResolver.FinalMember member,
            String owner,
            String name) {
        assertEquals(owner, member.getOwnerInternalName());
        assertEquals(name, member.getMemberName());
    }

    private static R8MappingResolver.FinalMember singleTarget(
            java.util.Set<R8MappingResolver.FinalMember> members) {
        assertEquals(1, members.size());
        return members.iterator().next();
    }

    private static Path writeMapping(String... lines) throws IOException {
        Path mapping = Files.createTempFile("dex-cfg-obf-exact-r8-", ".txt");
        Files.write(mapping, Arrays.asList(lines), StandardCharsets.UTF_8);
        return mapping;
    }
}
