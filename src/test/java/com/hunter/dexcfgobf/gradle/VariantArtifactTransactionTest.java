package com.hunter.dexcfgobf.gradle;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class VariantArtifactTransactionTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void secondDirectoryFailureRestoresEveryDexAndDeletesNewSidecars() throws Exception {
        Fixture fixture = fixture();
        byte[] firstBefore = bytes("first-before");
        byte[] secondBefore = bytes("second-before");
        Files.write(fixture.firstDex, firstBefore);
        Files.write(fixture.secondDex, secondBefore);

        try (VariantArtifactTransaction transaction =
                     VariantArtifactTransaction.begin(fixture.lock.toFile())) {
            transaction.captureFile(fixture.newEvidence.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newState.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newPending.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newReport.toFile(), fixture.buildRoot.toFile());
            transaction.captureDexDirectory(fixture.firstDex.getParent().toFile());
            transaction.captureDexDirectory(fixture.secondDex.getParent().toFile());

            Files.write(fixture.firstDex, bytes("first-obfuscated"));
            Files.write(fixture.secondDex, bytes("second-partial-failure"));
            writeNew(fixture.newEvidence, "evidence");
            writeNew(fixture.newState, "state");
            writeNew(fixture.newPending, "pending");
            writeNew(fixture.newReport, "report");
            transaction.rollback();
        }

        assertArrayEquals(firstBefore, Files.readAllBytes(fixture.firstDex));
        assertArrayEquals(secondBefore, Files.readAllBytes(fixture.secondDex));
        assertFalse(Files.exists(fixture.newEvidence));
        assertFalse(Files.exists(fixture.newState));
        assertFalse(Files.exists(fixture.newPending));
        assertFalse(Files.exists(fixture.newReport));
    }

    @Test
    public void stringGateFailureRestoresExistingSidecarsAndReport() throws Exception {
        Fixture fixture = fixture();
        byte[] dexBefore = bytes("dex-before-string-gate");
        Files.write(fixture.firstDex, dexBefore);
        writeNew(fixture.newEvidence, "old-evidence");
        writeNew(fixture.newState, "old-state");
        writeNew(fixture.newPending, "old-pending");
        writeNew(fixture.newReport, "old-report");

        try (VariantArtifactTransaction transaction =
                     VariantArtifactTransaction.begin(fixture.lock.toFile())) {
            transaction.captureFile(fixture.newEvidence.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newState.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newPending.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newReport.toFile(), fixture.buildRoot.toFile());
            transaction.captureDexDirectory(fixture.firstDex.getParent().toFile());

            Files.write(fixture.firstDex, bytes("dex-after-cfg"));
            Files.write(fixture.newEvidence, bytes("new-evidence"));
            Files.write(fixture.newState, bytes("new-state"));
            Files.delete(fixture.newPending);
            Files.write(fixture.newReport, bytes("failed-report"));
            // Simulate the exact catch path used for a final plaintext/string-scope gate failure.
            transaction.rollback();
        }

        assertArrayEquals(dexBefore, Files.readAllBytes(fixture.firstDex));
        assertArrayEquals(bytes("old-evidence"), Files.readAllBytes(fixture.newEvidence));
        assertArrayEquals(bytes("old-state"), Files.readAllBytes(fixture.newState));
        assertArrayEquals(bytes("old-pending"), Files.readAllBytes(fixture.newPending));
        assertArrayEquals(bytes("old-report"), Files.readAllBytes(fixture.newReport));
    }

    @Test
    public void evidenceCommitFailureRestoresEarlierDirectoryAndMixedSidecars() throws Exception {
        Fixture fixture = fixture();
        byte[] firstBefore = bytes("first-original");
        byte[] secondBefore = bytes("second-original");
        Files.write(fixture.firstDex, firstBefore);
        Files.write(fixture.secondDex, secondBefore);
        writeNew(fixture.newEvidence, "old-evidence");

        try (VariantArtifactTransaction transaction =
                     VariantArtifactTransaction.begin(fixture.lock.toFile())) {
            transaction.captureFile(fixture.newEvidence.toFile(), fixture.buildRoot.toFile());
            transaction.captureFile(fixture.newState.toFile(), fixture.buildRoot.toFile());
            transaction.captureDexDirectory(fixture.firstDex.getParent().toFile());
            transaction.captureDexDirectory(fixture.secondDex.getParent().toFile());

            Files.write(fixture.firstDex, bytes("first-committed"));
            Files.write(fixture.secondDex, bytes("second-committed"));
            Files.write(fixture.newEvidence, bytes("partially-written-new-evidence"));
            writeNew(fixture.newState, "new-state-before-evidence-failure");
            transaction.rollback();
        }

        assertArrayEquals(firstBefore, Files.readAllBytes(fixture.firstDex));
        assertArrayEquals(secondBefore, Files.readAllBytes(fixture.secondDex));
        assertArrayEquals(bytes("old-evidence"), Files.readAllBytes(fixture.newEvidence));
        assertFalse(Files.exists(fixture.newState));
    }

    @Test
    public void successKeepsDexAndSidecarMutations() throws Exception {
        Fixture fixture = fixture();
        Files.write(fixture.firstDex, bytes("before"));

        try (VariantArtifactTransaction transaction =
                     VariantArtifactTransaction.begin(fixture.lock.toFile())) {
            transaction.captureFile(fixture.newEvidence.toFile(), fixture.buildRoot.toFile());
            transaction.captureDexDirectory(fixture.firstDex.getParent().toFile());
            Files.write(fixture.firstDex, bytes("after"));
            writeNew(fixture.newEvidence, "committed-evidence");
            transaction.commit();
        }

        assertArrayEquals(bytes("after"), Files.readAllBytes(fixture.firstDex));
        assertArrayEquals(bytes("committed-evidence"), Files.readAllBytes(fixture.newEvidence));
    }

    @Test
    public void failedRestoreRetainsJournalAfterClose() throws Exception {
        Fixture fixture = fixture();
        writeNew(fixture.newEvidence, "recoverable-old-evidence");
        Path journalParent = fixture.lock.getParent();
        IOException rollbackFailure;

        try (VariantArtifactTransaction transaction =
                     VariantArtifactTransaction.begin(fixture.lock.toFile())) {
            transaction.captureFile(fixture.newEvidence.toFile(), fixture.buildRoot.toFile());
            Files.delete(fixture.newEvidence);
            Files.createDirectory(fixture.newEvidence);
            Files.write(fixture.newEvidence.resolve("blocker"), bytes("not-a-file-target"));
            rollbackFailure = assertThrows(IOException.class, transaction::rollback);
            assertTrue(rollbackFailure.getMessage().contains("journal retained at"));
        }

        List<Path> journals;
        try (Stream<Path> children = Files.list(journalParent)) {
            journals = children.filter(path -> path.getFileName().toString()
                            .startsWith(".dexcfgobf-variant-transaction-"))
                    .collect(Collectors.toList());
        }
        assertFalse("failed rollback journal must survive close", journals.isEmpty());
        boolean containsBackup = false;
        for (Path journal : journals) {
            try (Stream<Path> files = Files.walk(journal)) {
                if (files.anyMatch(path -> Files.isRegularFile(path)
                        && path.getFileName().toString().endsWith(".bin"))) {
                    containsBackup = true;
                    break;
                }
            }
        }
        assertTrue("failed rollback journal must retain exact file backups", containsBackup);
    }

    @Test
    public void rejectsTargetsOutsideAllowedRootAndDexSymlinks() throws Exception {
        Fixture fixture = fixture();
        Files.write(fixture.firstDex, bytes("first"));
        Path outside = temporary.newFile("outside.evidence").toPath();

        try (VariantArtifactTransaction transaction =
                     VariantArtifactTransaction.begin(fixture.lock.toFile())) {
            assertThrows(IOException.class, () -> transaction.captureFile(
                    outside.toFile(), fixture.buildRoot.toFile()));
            if (supportsSymbolicLinks(fixture)) {
                assertThrows(IOException.class, () -> transaction.captureDexDirectory(
                        fixture.firstDex.getParent().toFile()));
            }
            transaction.rollback();
        }
        assertArrayEquals(bytes("first"), Files.readAllBytes(fixture.firstDex));
    }

    private Fixture fixture() throws Exception {
        Path root = temporary.newFolder().toPath();
        Path build = Files.createDirectories(root.resolve("build"));
        Path first = Files.createDirectories(build.resolve("dex/first")).resolve("classes.dex");
        Path second = Files.createDirectories(build.resolve("dex/second")).resolve("classes2.dex");
        Path sidecars = build.resolve("intermediates/evidence/release");
        Path reports = build.resolve("reports/dex-cfg-obfuscator");
        return new Fixture(build, first, second,
                sidecars.resolve("release.cfg.evidence"),
                sidecars.resolve("release.state"),
                sidecars.resolve("release.pending"),
                reports.resolve("release.json"),
                root.resolve(".gradle/dex-cfg-obfuscator-locks/release.lock"));
    }

    private static boolean supportsSymbolicLinks(Fixture fixture) throws Exception {
        Path link = fixture.firstDex.getParent().resolve("linked-input");
        try {
            Files.createSymbolicLink(link, fixture.secondDex.getParent());
            return true;
        } catch (UnsupportedOperationException | IOException | SecurityException ignored) {
            return false;
        }
    }

    private static void writeNew(Path path, String value) throws IOException {
        Files.createDirectories(path.getParent());
        Files.write(path, bytes(value));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static final class Fixture {
        final Path buildRoot;
        final Path firstDex;
        final Path secondDex;
        final Path newEvidence;
        final Path newState;
        final Path newPending;
        final Path newReport;
        final Path lock;

        Fixture(Path buildRoot, Path firstDex, Path secondDex, Path newEvidence,
                Path newState, Path newPending, Path newReport, Path lock) {
            this.buildRoot = buildRoot;
            this.firstDex = firstDex;
            this.secondDex = secondDex;
            this.newEvidence = newEvidence;
            this.newState = newState;
            this.newPending = newPending;
            this.newReport = newReport;
            this.lock = lock;
        }
    }
}
