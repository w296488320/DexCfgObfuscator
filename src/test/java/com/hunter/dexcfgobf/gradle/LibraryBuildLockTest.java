package com.hunter.dexcfgobf.gradle;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class LibraryBuildLockTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void acquireIsIdempotentAndReleaseUnlocksTheInode() throws Exception {
        File lockFile = temporary.newFile("library.lock");
        String lockId = UUID.randomUUID().toString();
        LibraryBuildLock.acquire(lockId, lockFile);
        try {
            LibraryBuildLock.acquire(lockId, lockFile);
            try (FileChannel competitor = FileChannel.open(lockFile.toPath(),
                    StandardOpenOption.WRITE)) {
                try {
                    competitor.tryLock();
                    fail("the lock must remain held until release");
                } catch (OverlappingFileLockException expected) {
                    // Same-JVM competitor observes the live OS lock.
                }
            }
        } finally {
            LibraryBuildLock.release(lockId);
        }

        try (FileChannel competitor = FileChannel.open(lockFile.toPath(),
                StandardOpenOption.WRITE);
             FileLock acquired = competitor.tryLock()) {
            assertNotNull("release must unlock the inode", acquired);
        }
    }

    @Test
    public void oneIdCannotSilentlyAliasTwoLockFiles() throws Exception {
        File first = temporary.newFile("first.lock");
        File second = temporary.newFile("second.lock");
        String lockId = UUID.randomUUID().toString();
        LibraryBuildLock.acquire(lockId, first);
        try {
            try {
                LibraryBuildLock.acquire(lockId, second);
                fail("mismatched lock paths must fail closed");
            } catch (IllegalStateException expected) {
                // Expected.
            }
        } finally {
            LibraryBuildLock.release(lockId);
        }
    }
}
