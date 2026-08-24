package com.hunter.dexcfgobf.gradle;

import java.io.File;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Variant-wide rollback journal for the application post-DEX pipeline.
 *
 * <p>The Gradle task mutates another task's DEX outputs in place and then runs several gates. The
 * core transformer is directory-atomic, but a later directory, string gate, evidence write or
 * report write can still fail after an earlier directory has committed. This journal snapshots
 * only the exact DEX and sidecar files the task may write and restores each file through an atomic
 * sibling replacement on failure. It deliberately never recursively deletes a captured target.</p>
 *
 * <p>The OS lock lives outside the Android build directory so a concurrent {@code clean} cannot
 * unlink the coordination inode. A hard process kill is handled by the existing pending evidence;
 * this class covers every exception that reaches the Gradle action.</p>
 */
public final class VariantArtifactTransaction implements AutoCloseable {
    private final Path backupRoot;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private final Map<Path, Snapshot> snapshots = new LinkedHashMap<>();
    private boolean finished;
    private boolean committed;
    private boolean rollbackSucceeded;
    private boolean cleanupAllowed;

    private VariantArtifactTransaction(Path backupRoot, FileChannel lockChannel, FileLock lock) {
        this.backupRoot = backupRoot;
        this.lockChannel = lockChannel;
        this.lock = lock;
    }

    /** Acquires one exclusive application-variant lock and creates its private rollback area. */
    public static VariantArtifactTransaction begin(File lockFile) throws IOException {
        Objects.requireNonNull(lockFile, "lockFile");
        Path lockPath = lockFile.toPath().toAbsolutePath().normalize();
        Path parent = lockPath.getParent();
        if (parent == null) throw new IOException("variant transaction lock has no parent");
        Files.createDirectories(parent);
        rejectSymbolicLink(lockPath, "variant transaction lock");
        if (Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(lockPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("variant transaction lock is not a regular file: " + lockPath);
        }

        FileChannel channel = null;
        FileLock acquired = null;
        Path backup = null;
        try {
            channel = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE);
            acquired = channel.lock();
            backup = Files.createTempDirectory(parent, ".dexcfgobf-variant-transaction-");
            return new VariantArtifactTransaction(backup, channel, acquired);
        } catch (Throwable failure) {
            if (acquired != null) {
                try {
                    acquired.release();
                } catch (Throwable releaseFailure) {
                    failure.addSuppressed(releaseFailure);
                }
            }
            if (channel != null) {
                try {
                    channel.close();
                } catch (Throwable closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
            }
            deleteTreeBestEffort(backup);
            if (failure instanceof IOException) throw (IOException) failure;
            if (failure instanceof RuntimeException) throw (RuntimeException) failure;
            if (failure instanceof Error) throw (Error) failure;
            throw new IOException("cannot acquire variant transaction lock", failure);
        }
    }

    /** Snapshots every regular {@code *.dex} below one fresh producer directory. */
    public void captureDexDirectory(File dexDirectory) throws IOException {
        ensureOpen();
        Objects.requireNonNull(dexDirectory, "dexDirectory");
        Path root = dexDirectory.toPath().toAbsolutePath().normalize();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("DEX transaction root is not a directory: " + root);
        }
        rejectSymbolicLink(root, "DEX transaction root");
        Path realRoot = root.toRealPath();
        List<Path> dexFiles = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(root)) {
            paths.sorted().forEach(path -> {
                try {
                    if (Files.isSymbolicLink(path)) {
                        throw new SnapshotRuntimeException(new IOException(
                                "symbolic links are forbidden in a DEX transaction root: " + path));
                    }
                    if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                            && path.getFileName().toString().endsWith(".dex")) {
                        Path real = path.toRealPath();
                        if (!real.startsWith(realRoot)) {
                            throw new SnapshotRuntimeException(new IOException(
                                    "DEX path escapes transaction root: " + path));
                        }
                        dexFiles.add(path.toAbsolutePath().normalize());
                    }
                } catch (IOException failure) {
                    throw new SnapshotRuntimeException(failure);
                }
            });
        } catch (SnapshotRuntimeException failure) {
            throw failure.ioCause;
        }
        if (dexFiles.isEmpty()) {
            throw new IOException("DEX transaction root contains no DEX files: " + root);
        }
        for (Path dex : dexFiles) capture(dex, root);
    }

    /**
     * Snapshots one exact sidecar. The target may not exist yet; on rollback a newly created regular
     * file is deleted. Both existing and future targets must remain below {@code allowedRoot}.
     */
    public void captureFile(File targetFile, File allowedRoot) throws IOException {
        ensureOpen();
        Objects.requireNonNull(targetFile, "targetFile");
        Objects.requireNonNull(allowedRoot, "allowedRoot");
        capture(targetFile.toPath().toAbsolutePath().normalize(),
                allowedRoot.toPath().toAbsolutePath().normalize());
    }

    /** Keeps all current target bytes and discards the rollback journal. */
    public void commit() {
        ensureOpen();
        committed = true;
        finished = true;
        cleanupAllowed = true;
        deleteTreeBestEffort(backupRoot);
    }

    /** Restores every target to its exact pre-transaction existence and bytes. */
    public void rollback() throws IOException {
        if (finished) return;
        IOException aggregate = null;
        List<Snapshot> reverse = new ArrayList<>(snapshots.values());
        java.util.Collections.reverse(reverse);
        for (Snapshot snapshot : reverse) {
            try {
                restore(snapshot);
            } catch (Exception failure) {
                if (aggregate == null) {
                    aggregate = new IOException("variant artifact rollback was incomplete; "
                            + "journal retained at " + backupRoot);
                }
                aggregate.addSuppressed(failure);
            }
        }
        finished = true;
        if (aggregate == null) {
            rollbackSucceeded = true;
            cleanupAllowed = true;
            deleteTreeBestEffort(backupRoot);
        }
        if (aggregate != null) throw aggregate;
    }

    @Override
    public void close() throws IOException {
        IOException aggregate = null;
        if (!finished) {
            try {
                rollback();
            } catch (IOException failure) {
                aggregate = failure;
            }
        }
        try {
            if (lock.isValid()) lock.release();
        } catch (IOException failure) {
            aggregate = append(aggregate, failure);
        }
        try {
            lockChannel.close();
        } catch (IOException failure) {
            aggregate = append(aggregate, failure);
        }
        if (cleanupAllowed && (committed || rollbackSucceeded) && aggregate == null) {
            deleteTreeBestEffort(backupRoot);
        }
        if (aggregate != null) throw aggregate;
    }

    private void capture(Path target, Path allowedRoot) throws IOException {
        validateContained(target, allowedRoot);
        if (snapshots.containsKey(target)) return;

        boolean exists = Files.exists(target, LinkOption.NOFOLLOW_LINKS);
        Path backup = null;
        if (exists) {
            rejectSymbolicLink(target, "transaction target");
            if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("transaction target is not a regular file: " + target);
            }
            backup = backupRoot.resolve(String.format(java.util.Locale.ROOT, "%08d.bin",
                    snapshots.size()));
            Files.copy(target, backup, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.COPY_ATTRIBUTES);
        }
        snapshots.put(target, new Snapshot(target, allowedRoot, exists, backup));
    }

    private static void restore(Snapshot snapshot) throws IOException {
        validateContained(snapshot.target, snapshot.allowedRoot);
        if (!snapshot.existed) {
            if (!Files.exists(snapshot.target, LinkOption.NOFOLLOW_LINKS)) return;
            rejectSymbolicLink(snapshot.target, "new transaction target");
            if (!Files.isRegularFile(snapshot.target, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("refusing broad rollback delete of non-file target: "
                        + snapshot.target);
            }
            Files.delete(snapshot.target);
            return;
        }

        if (snapshot.backup == null || !Files.isRegularFile(snapshot.backup)) {
            throw new IOException("transaction backup is missing: " + snapshot.target);
        }
        Path parent = snapshot.target.getParent();
        if (parent == null) throw new IOException("transaction target has no parent");
        Files.createDirectories(parent);
        validateContained(snapshot.target, snapshot.allowedRoot);
        rejectSymbolicLink(snapshot.target, "transaction restore target");
        if (Files.exists(snapshot.target, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(snapshot.target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("transaction restore target is not a regular file: "
                    + snapshot.target);
        }
        Path temporary = Files.createTempFile(parent, ".dexcfgobf-restore-", ".tmp");
        try {
            Files.copy(snapshot.backup, temporary, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.COPY_ATTRIBUTES);
            try {
                Files.move(temporary, snapshot.target, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, snapshot.target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void validateContained(Path target, Path allowedRoot) throws IOException {
        Path normalizedRoot = allowedRoot.toAbsolutePath().normalize();
        Path normalizedTarget = target.toAbsolutePath().normalize();
        if (!Files.isDirectory(normalizedRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("transaction allowed root is not a directory: " + normalizedRoot);
        }
        rejectSymbolicLink(normalizedRoot, "transaction allowed root");
        if (!normalizedTarget.startsWith(normalizedRoot) || normalizedTarget.equals(normalizedRoot)) {
            throw new IOException("transaction target escapes allowed root: " + normalizedTarget);
        }

        Path current = normalizedRoot;
        Path relative = normalizedRoot.relativize(normalizedTarget);
        for (Path component : relative) {
            current = current.resolve(component);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)
                    && Files.isSymbolicLink(current)) {
                throw new IOException("symbolic link in transaction target path: " + current);
            }
        }
        Path realRoot = normalizedRoot.toRealPath();
        Path existingParent = normalizedTarget.getParent();
        while (existingParent != null
                && !Files.exists(existingParent, LinkOption.NOFOLLOW_LINKS)) {
            existingParent = existingParent.getParent();
        }
        if (existingParent == null || !existingParent.toRealPath().startsWith(realRoot)) {
            throw new IOException("transaction target parent escapes allowed root: "
                    + normalizedTarget);
        }
    }

    private static void rejectSymbolicLink(Path path, String label) throws IOException {
        if (Files.isSymbolicLink(path)) {
            throw new IOException(label + " must not be a symbolic link: " + path);
        }
    }

    private void ensureOpen() {
        if (finished) throw new IllegalStateException("variant artifact transaction is finished");
    }

    private static IOException append(IOException aggregate, IOException failure) {
        if (aggregate == null) aggregate = new IOException("cannot close variant artifact transaction");
        aggregate.addSuppressed(failure);
        return aggregate;
    }

    private static void deleteTreeBestEffort(Path root) {
        if (root == null || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return;
        try (Stream<Path> paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // A leaked private backup is safer than turning a successful artifact into failure.
                }
            });
        } catch (IOException ignored) {
            // Best-effort cleanup only; target files have already reached their final state.
        }
    }

    private static final class Snapshot {
        final Path target;
        final Path allowedRoot;
        final boolean existed;
        final Path backup;

        Snapshot(Path target, Path allowedRoot, boolean existed, Path backup) {
            this.target = target;
            this.allowedRoot = allowedRoot;
            this.existed = existed;
            this.backup = backup;
        }
    }

    private static final class SnapshotRuntimeException extends RuntimeException {
        final IOException ioCause;

        SnapshotRuntimeException(IOException cause) {
            super(cause);
            this.ioCause = cause;
        }
    }
}
