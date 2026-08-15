package com.hunter.dexcfgobf;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class DexDirectoryStateTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void exactPostTransformFingerprintIsSkippedUntilDexChanges() throws Exception {
        File dexDir = temporary.newFolder("producer");
        File dex = new File(dexDir, "classes.dex");
        Files.write(dex.toPath(), "first".getBytes(StandardCharsets.UTF_8));
        File stateRoot = temporary.newFolder("state");
        File stateFile = DexDirectoryState.stateFile(stateRoot, dexDir);

        String transformed = DexDirectoryState.fingerprint(dexDir);
        assertFalse(DexDirectoryState.matches(stateFile, transformed));

        DexDirectoryState.write(stateFile, transformed);
        assertTrue(DexDirectoryState.matches(stateFile, DexDirectoryState.fingerprint(dexDir)));

        Files.write(dex.toPath(), "second".getBytes(StandardCharsets.UTF_8));
        assertFalse(DexDirectoryState.matches(stateFile, DexDirectoryState.fingerprint(dexDir)));
    }

    @Test
    public void nonDexFilesDoNotInvalidateProducerFingerprint() throws Exception {
        File dexDir = temporary.newFolder("producer-with-metadata");
        Files.write(new File(dexDir, "classes.dex").toPath(), new byte[]{1, 2, 3});
        String before = DexDirectoryState.fingerprint(dexDir);

        Files.write(new File(dexDir, "metadata.txt").toPath(), new byte[]{9, 8, 7});

        assertTrue(before.equals(DexDirectoryState.fingerprint(dexDir)));
    }

    @Test
    public void relativeDexPathParticipatesInFingerprint() throws Exception {
        File first = temporary.newFolder("first-layout");
        File second = temporary.newFolder("second-layout");
        Files.write(new File(first, "classes.dex").toPath(), new byte[]{1, 2, 3});
        File nested = new File(second, "nested");
        assertTrue(nested.mkdirs());
        Files.write(new File(nested, "classes.dex").toPath(), new byte[]{1, 2, 3});

        assertNotEquals(DexDirectoryState.fingerprint(first), DexDirectoryState.fingerprint(second));
    }
}
