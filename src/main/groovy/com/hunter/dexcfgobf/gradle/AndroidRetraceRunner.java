package com.hunter.dexcfgobf.gradle;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** Runs the Android SDK's official R8 retrace command without exposing crash contents to logs. */
final class AndroidRetraceRunner {
    static final long DEFAULT_TIMEOUT_MILLIS = TimeUnit.SECONDS.toMillis(120);

    enum Result {
        RETRACED,
        COPIED_UNCHANGED
    }

    private AndroidRetraceRunner() {
    }

    static Result run(Path traceFile, Path outputFile, Path mappingFile,
                      boolean minified, Path explicitExecutable) throws IOException {
        return run(traceFile, outputFile, mappingFile, minified, explicitExecutable, null);
    }

    static Result run(Path traceFile, Path outputFile, Path mappingFile,
                      boolean minified, Path explicitExecutable, Path explicitSdkDirectory)
            throws IOException {
        return run(traceFile, outputFile, mappingFile, minified, explicitExecutable,
                explicitSdkDirectory, System.getenv(), System.getProperty("os.name", ""));
    }

    static Result run(Path traceFile, Path outputFile, Path mappingFile,
                      boolean minified, Path explicitExecutable,
                      Map<String, String> environment, String osName) throws IOException {
        return run(traceFile, outputFile, mappingFile, minified, explicitExecutable, null,
                environment, osName);
    }

    static Result run(Path traceFile, Path outputFile, Path mappingFile,
                      boolean minified, Path explicitExecutable, Path explicitSdkDirectory,
                      Map<String, String> environment, String osName) throws IOException {
        return run(traceFile, outputFile, mappingFile, minified, explicitExecutable,
                explicitSdkDirectory, environment, osName, DEFAULT_TIMEOUT_MILLIS);
    }

    static Result run(Path traceFile, Path outputFile, Path mappingFile,
                      boolean minified, Path explicitExecutable, Path explicitSdkDirectory,
                      Map<String, String> environment, String osName, long timeoutMillis)
            throws IOException {
        if (timeoutMillis <= 0) {
            throw new IllegalArgumentException("retrace timeout must be positive");
        }
        Path trace = requireReadableFile(traceFile, "stack-trace input");
        Path output = normalize(outputFile, "stack-trace output");
        rejectInPlaceOutput(trace, output);

        if (!minified) {
            writeAtomically(output, temporary -> Files.copy(trace, temporary,
                    StandardCopyOption.REPLACE_EXISTING));
            return Result.COPIED_UNCHANGED;
        }
        Path mapping = readableFileOrNull(mappingFile);
        if (mapping == null) {
            throw new IOException("R8 mapping.txt is required for a minified variant; refusing "
                    + "to emit a misleading unchanged stack trace");
        }

        Path executable = explicitExecutable == null
                ? locate(explicitSdkDirectory, environment, osName)
                : requireExecutable(explicitExecutable, osName, "configured Android retrace");
        if (executable == null) {
            throw new IOException("Android SDK retrace was not found. Install SDK command-line "
                    + "tools and set ANDROID_HOME or ANDROID_SDK_ROOT, or configure an explicit "
                    + "retrace executable.");
        }

        writeAtomically(output, temporary -> runProcess(
                executable, mapping, trace, temporary, environment, osName, timeoutMillis));
        return Result.RETRACED;
    }

    static Path locate(Map<String, String> environment, String osName) throws IOException {
        return locate(null, environment, osName);
    }

    static Path locate(Path explicitSdkDirectory, Map<String, String> environment, String osName)
            throws IOException {
        boolean windows = isWindows(osName);
        String executableName = windows ? "retrace.bat" : "retrace";
        Set<Path> sdkRoots = new LinkedHashSet<>();
        addSdkRoot(sdkRoots, explicitSdkDirectory);
        addSdkRoot(sdkRoots, environment == null ? null : environment.get("ANDROID_HOME"));
        addSdkRoot(sdkRoots, environment == null ? null : environment.get("ANDROID_SDK_ROOT"));

        for (Path sdkRoot : sdkRoots) {
            Path commandLineTools = sdkRoot.resolve("cmdline-tools");
            Path latest = commandLineTools.resolve("latest").resolve("bin")
                    .resolve(executableName);
            if (isExecutable(latest, windows)) {
                return latest.toAbsolutePath().normalize();
            }
            if (!Files.isDirectory(commandLineTools)) {
                continue;
            }

            List<Path> versions = new ArrayList<>();
            try (Stream<Path> children = Files.list(commandLineTools)) {
                children.filter(Files::isDirectory)
                        .filter(path -> !"latest".equalsIgnoreCase(
                                path.getFileName().toString()))
                        .forEach(versions::add);
            }
            versions.sort(Comparator.comparing(
                    (Path path) -> path.getFileName().toString(),
                    AndroidRetraceRunner::compareVersionNames).reversed());
            for (Path version : versions) {
                Path candidate = version.resolve("bin").resolve(executableName);
                if (isExecutable(candidate, windows)) {
                    return candidate.toAbsolutePath().normalize();
                }
            }
        }
        return null;
    }

    static Path defaultOutput(Path traceFile) {
        Path trace = normalize(traceFile, "stack-trace input");
        Path fileName = trace.getFileName();
        if (fileName == null) {
            throw new IllegalArgumentException("stack-trace input has no file name");
        }
        String name = fileName.toString();
        int extension = name.lastIndexOf('.');
        String retracedName = extension > 0
                ? name.substring(0, extension) + ".retraced" + name.substring(extension)
                : name + ".retraced.txt";
        Path parent = trace.getParent();
        return parent == null ? Path.of(retracedName) : parent.resolve(retracedName);
    }

    private static void runProcess(Path executable, Path mapping, Path trace, Path output,
                                   Map<String, String> environment, String osName,
                                   long timeoutMillis)
            throws IOException {
        List<String> command = buildCommand(executable, mapping, trace, environment, osName);
        Process process = new ProcessBuilder(command)
                .redirectOutput(output.toFile())
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        boolean completed;
        try {
            completed = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            destroyProcessTree(process);
            Thread.currentThread().interrupt();
            throw new IOException("Android retrace was interrupted", interrupted);
        }
        if (!completed) {
            destroyProcessTree(process);
            throw new IOException("Android retrace timed out after " + timeoutMillis
                    + " ms; stack-trace contents were not logged");
        }
        int status = process.exitValue();
        if (status != 0) {
            throw new IOException("Android retrace failed with exit code " + status
                    + "; stack-trace contents were not logged");
        }
    }

    private static void destroyProcessTree(Process process) {
        process.toHandle().descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        try {
            process.waitFor(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    static List<String> buildCommand(Path executable, Path mapping, Path trace,
                                     Map<String, String> environment, String osName)
            throws IOException {
        if (!isWindows(osName)
                || !executable.getFileName().toString().toLowerCase(Locale.ROOT)
                .endsWith(".bat")) {
            return List.of(executable.toString(), mapping.toString(), trace.toString());
        }
        String executableArgument = safeCmdPath(executable);
        String mappingArgument = safeCmdPath(mapping);
        String traceArgument = safeCmdPath(trace);
        String commandInterpreter = environment == null ? null : environment.get("COMSPEC");
        if (commandInterpreter == null || commandInterpreter.trim().isEmpty()) {
            commandInterpreter = "cmd.exe";
        }
        String commandLine = "\"" + executableArgument + "\" \"" + mappingArgument
                + "\" \"" + traceArgument + "\"";
        return List.of(commandInterpreter, "/d", "/v:off", "/s", "/c",
                "\"" + commandLine + "\"");
    }

    private static String safeCmdPath(Path value) throws IOException {
        String path = value.toString();
        for (int i = 0; i < path.length(); i++) {
            char character = path.charAt(i);
            if (character == '"' || character == '&' || character == '|'
                    || character == '<' || character == '>' || character == '^'
                    || character == '%' || character == '!' || character == '\r'
                    || character == '\n') {
                throw new IOException("Windows retrace path contains a cmd.exe metacharacter; "
                        + "move the mapping, trace, or SDK to a plain path");
            }
        }
        return path;
    }

    private static void writeAtomically(Path output, AtomicWriter writer) throws IOException {
        Path absolute = output.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new IOException("stack-trace output has no parent directory: " + output);
        }
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".dexcfg-retrace-", ".tmp");
        boolean committed = false;
        try {
            writer.write(temporary);
            try {
                Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
            committed = true;
        } finally {
            if (!committed) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static Path readableFileOrNull(Path file) throws IOException {
        if (file == null) {
            return null;
        }
        Path path = file.toAbsolutePath().normalize();
        if (!Files.exists(path)) {
            return null;
        }
        return requireReadableFile(path, "R8 mapping");
    }

    private static Path requireReadableFile(Path file, String label) throws IOException {
        Path path = normalize(file, label).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IOException(label + " must be a readable regular file: " + path);
        }
        return path;
    }

    private static Path requireExecutable(Path file, String osName, String label)
            throws IOException {
        Path path = normalize(file, label).toAbsolutePath().normalize();
        if (!isExecutable(path, isWindows(osName))) {
            throw new IOException(label + " must be an executable regular file: " + path);
        }
        return path;
    }

    private static boolean isExecutable(Path path, boolean windows) {
        return Files.isRegularFile(path) && (windows || Files.isExecutable(path));
    }

    private static void rejectInPlaceOutput(Path trace, Path output) throws IOException {
        Path normalizedTrace = trace.toAbsolutePath().normalize();
        Path normalizedOutput = output.toAbsolutePath().normalize();
        if (normalizedTrace.equals(normalizedOutput)
                || (Files.exists(normalizedOutput)
                && Files.isSameFile(normalizedTrace, normalizedOutput))) {
            throw new IOException("stack-trace output must not overwrite the input file");
        }
    }

    private static Path normalize(Path path, String label) {
        if (path == null) {
            throw new IllegalArgumentException(label + " is required");
        }
        return path.normalize();
    }

    private static void addSdkRoot(Set<Path> roots, String value) {
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        roots.add(Path.of(value.trim()).toAbsolutePath().normalize());
    }

    private static void addSdkRoot(Set<Path> roots, Path value) {
        if (value != null) {
            roots.add(value.toAbsolutePath().normalize());
        }
    }

    private static boolean isWindows(String osName) {
        return osName != null && osName.toLowerCase(Locale.ROOT).contains("win");
    }

    private static int compareVersionNames(String left, String right) {
        List<String> leftParts = versionParts(left);
        List<String> rightParts = versionParts(right);
        int common = Math.min(leftParts.size(), rightParts.size());
        for (int i = 0; i < common; i++) {
            String leftPart = leftParts.get(i);
            String rightPart = rightParts.get(i);
            boolean leftNumber = isNumber(leftPart);
            boolean rightNumber = isNumber(rightPart);
            int comparison;
            if (leftNumber && rightNumber) {
                comparison = compareNumericStrings(leftPart, rightPart);
            } else if (leftNumber != rightNumber) {
                comparison = leftNumber ? 1 : -1;
            } else {
                comparison = leftPart.compareToIgnoreCase(rightPart);
            }
            if (comparison != 0) {
                return comparison;
            }
        }
        return Integer.compare(leftParts.size(), rightParts.size());
    }

    private static List<String> versionParts(String value) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        Boolean numeric = null;
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (!Character.isLetterOrDigit(character)) {
                if (current.length() > 0) {
                    parts.add(current.toString());
                    current.setLength(0);
                }
                numeric = null;
                continue;
            }
            boolean nextNumeric = Character.isDigit(character);
            if (numeric != null && numeric != nextNumeric && current.length() > 0) {
                parts.add(current.toString());
                current.setLength(0);
            }
            current.append(character);
            numeric = nextNumeric;
        }
        if (current.length() > 0) {
            parts.add(current.toString());
        }
        return parts;
    }

    private static boolean isNumber(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return !value.isEmpty();
    }

    private static int compareNumericStrings(String left, String right) {
        String normalizedLeft = left.replaceFirst("^0+(?!$)", "");
        String normalizedRight = right.replaceFirst("^0+(?!$)", "");
        int length = Integer.compare(normalizedLeft.length(), normalizedRight.length());
        return length == 0 ? normalizedLeft.compareTo(normalizedRight) : length;
    }

    @FunctionalInterface
    private interface AtomicWriter {
        void write(Path output) throws IOException;
    }
}
