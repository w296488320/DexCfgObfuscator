package com.hunter.dexcfgobf;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Content fingerprint for an AGP DEX producer directory.
 *
 * <p>The Gradle adapter currently post-processes producer output in place. AGP can reuse that
 * directory on the next incremental build, so executing the obfuscator again would transform an
 * already transformed DEX. This state records the exact post-transform bytes outside the producer
 * directory and lets the adapter skip only an exact match.</p>
 */
public final class DexDirectoryState {
    private DexDirectoryState() {
    }

    public static String fingerprint(File dexDir) throws IOException {
        if (dexDir == null || !dexDir.isDirectory()) {
            throw new IOException("DEX directory does not exist: " + dexDir);
        }
        Path root = dexDir.toPath().toAbsolutePath().normalize();
        List<Path> dexFiles = new ArrayList<>();
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".dex"))
                    .forEach(dexFiles::add);
        }
        dexFiles.sort(Comparator.comparing(path -> normalizedRelativePath(root, path)));
        if (dexFiles.isEmpty()) {
            throw new IOException("No DEX files under " + dexDir);
        }

        MessageDigest digest = newSha256();
        byte[] buffer = new byte[64 * 1024];
        for (Path dex : dexFiles) {
            byte[] relative = normalizedRelativePath(root, dex).getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(relative.length).array());
            digest.update(relative);
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(Files.size(dex)).array());
            try (InputStream input = Files.newInputStream(dex)) {
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count > 0) digest.update(buffer, 0, count);
                }
            }
        }
        return toHex(digest.digest());
    }

    public static File stateFile(File stateRoot, File dexDir) throws IOException {
        String canonicalPath = dexDir.getCanonicalPath();
        MessageDigest digest = newSha256();
        digest.update(canonicalPath.getBytes(StandardCharsets.UTF_8));
        return new File(stateRoot, toHex(digest.digest()) + ".sha256");
    }

    public static boolean matches(File stateFile, String fingerprint) {
        if (stateFile == null || fingerprint == null || !stateFile.isFile()) {
            return false;
        }
        try {
            return fingerprint.equals(Files.readString(stateFile.toPath(), StandardCharsets.UTF_8).trim());
        } catch (IOException ignored) {
            return false;
        }
    }

    public static void write(File stateFile, String fingerprint) throws IOException {
        if (stateFile == null || fingerprint == null || fingerprint.isEmpty()) {
            throw new IOException("Invalid DEX state target or fingerprint");
        }
        Path target = stateFile.toPath();
        Path parent = target.toAbsolutePath().getParent();
        if (parent == null) {
            throw new IOException("DEX state file has no parent: " + stateFile);
        }
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".dex-state-", ".tmp");
        try {
            Files.writeString(temporary, fingerprint + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
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

    private static String normalizedRelativePath(Path root, Path file) {
        return root.relativize(file.toAbsolutePath().normalize()).toString()
                .replace(File.separatorChar, '/');
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String toHex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }
}
