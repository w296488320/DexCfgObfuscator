package com.hunter.dexcfgobf.gradle;

import org.gradle.api.flow.FlowAction;
import org.gradle.api.flow.FlowParameters;
import org.gradle.api.flow.FlowProviders;
import org.gradle.api.flow.FlowScope;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;

import java.io.File;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;

/** Cross-process lock held until Gradle's complete build-work flow has finished. */
public final class LibraryBuildLock {
    private static final Object MONITOR = new Object();
    private static final Map<String, Holder> HELD = new HashMap<>();

    private LibraryBuildLock() {
    }

    /** Registers a configuration-cache-aware end-of-build release action. */
    public static void registerRelease(FlowScope flowScope, FlowProviders flowProviders,
                                       String lockId) {
        flowScope.always(ReleaseAction.class, spec -> {
            spec.getParameters().getLockId().set(lockId);
            // This provider becomes available after all scheduled work, including failures.
            spec.getParameters().getCompletionSignal().set(
                    flowProviders.getBuildWorkResult().map(ignored -> "build-work-finished"));
        });
    }

    /** Idempotent within one Gradle process; fail-fast against a second process. */
    public static void acquire(String lockId, File lockFile) {
        if (lockId == null || lockId.isEmpty()) {
            throw new IllegalArgumentException("library build lock id is missing");
        }
        if (lockFile == null) {
            throw new IllegalArgumentException("library build lock file is missing");
        }
        synchronized (MONITOR) {
            Holder existing = HELD.get(lockId);
            if (existing != null) {
                if (!existing.path.equals(canonical(lockFile))) {
                    throw new IllegalStateException("library build lock id maps to two paths: "
                            + lockId);
                }
                return;
            }
            Holder acquired = Holder.acquire(lockFile);
            HELD.put(lockId, acquired);
        }
    }

    static void release(String lockId) throws IOException {
        Holder holder;
        synchronized (MONITOR) {
            holder = HELD.remove(lockId);
        }
        if (holder != null) holder.close();
    }

    private static String canonical(File file) {
        try {
            return file.getCanonicalPath();
        } catch (IOException failure) {
            throw new IllegalStateException("cannot resolve library build lock path: " + file,
                    failure);
        }
    }

    /** Flow input is intentionally tied to BuildWorkResult so execute cannot run early. */
    public interface ReleaseParameters extends FlowParameters {
        @Input
        Property<String> getLockId();

        @Input
        Property<String> getCompletionSignal();
    }

    public abstract static class ReleaseAction implements FlowAction<ReleaseParameters> {
        @Override
        public void execute(ReleaseParameters parameters) throws Exception {
            parameters.getCompletionSignal().get();
            release(parameters.getLockId().get());
        }
    }

    private static final class Holder implements AutoCloseable {
        final String path;
        FileChannel channel;
        FileLock lock;

        private Holder(String path, FileChannel channel, FileLock lock) {
            this.path = path;
            this.channel = channel;
            this.lock = lock;
        }

        static Holder acquire(File lockFile) {
            FileChannel channel = null;
            String path = canonical(lockFile);
            try {
                File parent = lockFile.getAbsoluteFile().getParentFile();
                if (parent == null) {
                    throw new IOException("library build lock has no parent: " + lockFile);
                }
                Files.createDirectories(parent.toPath());
                channel = FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE);
                FileLock lock;
                try {
                    lock = channel.tryLock();
                } catch (OverlappingFileLockException overlap) {
                    throw new IllegalStateException("another task in this JVM already holds "
                            + "the library obfuscation build lock: " + lockFile, overlap);
                }
                if (lock == null) {
                    throw new IllegalStateException("another Gradle process is using the same "
                            + "library buildDir; use an isolated buildDir or wait for it to finish: "
                            + lockFile);
                }
                return new Holder(path, channel, lock);
            } catch (IOException | RuntimeException failure) {
                if (channel != null) {
                    try {
                        channel.close();
                    } catch (IOException closeFailure) {
                        failure.addSuppressed(closeFailure);
                    }
                }
                throw failure instanceof IllegalStateException
                        ? (IllegalStateException) failure
                        : new IllegalStateException("cannot acquire library obfuscation build lock: "
                        + lockFile, failure);
            }
        }

        @Override
        public void close() throws IOException {
            IOException failure = null;
            if (lock != null) {
                try {
                    lock.release();
                } catch (IOException releaseFailure) {
                    failure = releaseFailure;
                } finally {
                    lock = null;
                }
            }
            if (channel != null) {
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    if (failure == null) failure = closeFailure;
                    else failure.addSuppressed(closeFailure);
                } finally {
                    channel = null;
                }
            }
            if (failure != null) throw failure;
        }
    }
}
