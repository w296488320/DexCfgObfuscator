package com.hunter.dexcfgobf.gradle;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AndroidRetraceRunnerTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void explicitExecutableReceivesLiteralArgumentsAndWritesAtomically() throws Exception {
        Path root = temporary.newFolder("paths with spaces").toPath();
        Path marker = root.resolve("must-not-exist");
        Path trace = root.resolve("crash;touch must-not-exist.txt");
        Path mapping = root.resolve("mapping file.txt");
        Path output = root.resolve("retraced output.txt");
        Files.writeString(trace, "at a.b(SourceFile:7)\n", StandardCharsets.UTF_8);
        Files.writeString(mapping, "# mapping\n", StandardCharsets.UTF_8);
        Path executable = executable(root.resolve("fake retrace"),
                "#!/bin/sh\n"
                        + "printf 'official-retrace\\n'\n"
                        + "printf 'mapping=%s\\n' \"$(basename \"$1\")\"\n"
                        + "cat \"$2\"\n");

        AndroidRetraceRunner.Result result = AndroidRetraceRunner.run(
                trace, output, mapping, true, executable, Map.of(), "Linux");

        assertEquals(AndroidRetraceRunner.Result.RETRACED, result);
        String retraced = Files.readString(output, StandardCharsets.UTF_8);
        assertTrue(retraced.contains("official-retrace"));
        assertTrue(retraced.contains("mapping=mapping file.txt"));
        assertTrue(retraced.contains("at a.b(SourceFile:7)"));
        assertFalse("ProcessBuilder must not shell-expand input paths", Files.exists(marker));
        assertNoTemporaryOutput(root);
    }

    @Test
    public void minifiedBuildWithoutMappingFailsClosed() throws Exception {
        Path root = temporary.newFolder("missing-mapping").toPath();
        Path trace = root.resolve("crash.txt");
        Path output = root.resolve("result.txt");
        Files.writeString(trace, "private-stack-content\n", StandardCharsets.UTF_8);

        IOException failure = assertThrows(IOException.class,
                () -> AndroidRetraceRunner.run(
                        trace, output, root.resolve("missing-mapping.txt"), true,
                        root.resolve("missing-retrace"), Map.of(), "Linux"));

        assertTrue(failure.getMessage().contains("mapping.txt is required"));
        assertFalse(Files.exists(output));
        assertNoTemporaryOutput(root);
    }

    @Test
    public void nonMinifiedBuildCopiesUnchangedWithoutResolvingExecutable() throws Exception {
        Path root = temporary.newFolder("passthrough").toPath();
        Path trace = root.resolve("crash.txt");
        Path output = root.resolve("result.txt");
        String contents = "private-stack-content\n";
        Files.writeString(trace, contents, StandardCharsets.UTF_8);

        AndroidRetraceRunner.Result result = AndroidRetraceRunner.run(
                trace, output, root.resolve("missing-mapping.txt"), false,
                root.resolve("missing-retrace"), Map.of(), "Linux");

        assertEquals(AndroidRetraceRunner.Result.COPIED_UNCHANGED, result);
        assertEquals(contents, Files.readString(output, StandardCharsets.UTF_8));
        assertNoTemporaryOutput(root);
    }

    @Test
    public void nonzeroRetraceDoesNotReplaceExistingOutputOrExposeToolStderr() throws Exception {
        Path root = temporary.newFolder("failure").toPath();
        Path trace = root.resolve("crash.txt");
        Path mapping = root.resolve("mapping.txt");
        Path output = root.resolve("retraced.txt");
        Files.writeString(trace, "SECRET-STACK-LINE\n", StandardCharsets.UTF_8);
        Files.writeString(mapping, "# mapping\n", StandardCharsets.UTF_8);
        Files.writeString(output, "previous-good-output\n", StandardCharsets.UTF_8);
        Path executable = executable(root.resolve("failing-retrace"),
                "#!/bin/sh\n"
                        + "echo 'SECRET-STACK-LINE' >&2\n"
                        + "echo 'partial-output'\n"
                        + "exit 19\n");

        IOException failure = assertThrows(IOException.class,
                () -> AndroidRetraceRunner.run(trace, output, mapping, true, executable,
                        Map.of(), "Linux"));

        assertTrue(failure.getMessage().contains("exit code 19"));
        assertFalse(failure.getMessage().contains("SECRET-STACK-LINE"));
        assertEquals("previous-good-output\n",
                Files.readString(output, StandardCharsets.UTF_8));
        assertNoTemporaryOutput(root);
    }

    @Test
    public void rejectsReplacingInputThroughTheSamePath() throws Exception {
        Path trace = temporary.newFile("same.txt").toPath();
        IOException failure = assertThrows(IOException.class,
                () -> AndroidRetraceRunner.run(trace, trace, null, false, null,
                        Map.of(), "Linux"));
        assertTrue(failure.getMessage().contains("must not overwrite"));
    }

    @Test
    public void locatorPrefersLatestThenHighestNumericSdkVersion() throws Exception {
        Path sdk = temporary.newFolder("android sdk").toPath();
        Path versionNine = executable(sdk.resolve("cmdline-tools/9.0/bin/retrace"),
                "#!/bin/sh\nexit 0\n");
        Path versionTwentyOne = executable(sdk.resolve("cmdline-tools/21.0/bin/retrace"),
                "#!/bin/sh\nexit 0\n");
        Map<String, String> environment = Map.of("ANDROID_HOME", sdk.toString());

        assertEquals(versionTwentyOne.toAbsolutePath().normalize(),
                AndroidRetraceRunner.locate(environment, "Linux"));

        Path latest = executable(sdk.resolve("cmdline-tools/latest/bin/retrace"),
                "#!/bin/sh\nexit 0\n");
        assertEquals(latest.toAbsolutePath().normalize(),
                AndroidRetraceRunner.locate(environment, "Linux"));
        assertTrue(Files.exists(versionNine));
    }

    @Test
    public void locatorPrefersExplicitSdkDirectoryOverEnvironment() throws Exception {
        Path configuredSdk = temporary.newFolder("configured-sdk").toPath();
        Path environmentSdk = temporary.newFolder("environment-sdk").toPath();
        Path configured = executable(
                configuredSdk.resolve("cmdline-tools/latest/bin/retrace"),
                "#!/bin/sh\nexit 0\n");
        executable(environmentSdk.resolve("cmdline-tools/latest/bin/retrace"),
                "#!/bin/sh\nexit 0\n");

        assertEquals(configured.toAbsolutePath().normalize(),
                AndroidRetraceRunner.locate(configuredSdk,
                        Map.of("ANDROID_HOME", environmentSdk.toString()), "Linux"));
    }

    @Test
    public void windowsBatchUsesCmdArgumentVectorAndRejectsMetacharacters() throws Exception {
        Path executable = Path.of("C:\\Android SDK\\cmdline-tools\\latest\\bin\\retrace.bat");
        Path mapping = Path.of("C:\\symbols\\mapping.txt");
        Path trace = Path.of("C:\\crashes\\trace.txt");

        java.util.List<String> command = AndroidRetraceRunner.buildCommand(
                executable, mapping, trace, Map.of("COMSPEC", "C:\\Windows\\System32\\cmd.exe"),
                "Windows 11");

        assertEquals("C:\\Windows\\System32\\cmd.exe", command.get(0));
        assertEquals(java.util.List.of("/d", "/v:off", "/s", "/c"),
                command.subList(1, 5));
        assertTrue(command.get(5).contains("retrace.bat"));
        assertThrows(IOException.class, () -> AndroidRetraceRunner.buildCommand(
                executable, mapping, Path.of("C:\\crashes\\trace&whoami.txt"), Map.of(),
                "Windows 11"));
    }

    @Test
    public void timeoutKillsRetraceAndPreservesExistingOutput() throws Exception {
        Path root = temporary.newFolder("timeout").toPath();
        Path trace = root.resolve("crash.txt");
        Path mapping = root.resolve("mapping.txt");
        Path output = root.resolve("retraced.txt");
        Files.writeString(trace, "SECRET-TIMEOUT-STACK\n", StandardCharsets.UTF_8);
        Files.writeString(mapping, "# mapping\n", StandardCharsets.UTF_8);
        Files.writeString(output, "previous-good-output\n", StandardCharsets.UTF_8);
        Path executable = executable(root.resolve("slow-retrace"),
                "#!/bin/sh\n"
                        + "sleep 10\n"
                        + "cat \"$2\"\n");

        long started = System.nanoTime();
        IOException failure = assertThrows(IOException.class,
                () -> AndroidRetraceRunner.run(trace, output, mapping, true, executable,
                        null, Map.of(), "Linux", 100));
        long elapsedMillis = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - started);

        assertTrue(failure.getMessage().contains("timed out"));
        assertFalse(failure.getMessage().contains("SECRET-TIMEOUT-STACK"));
        assertTrue("timeout must terminate promptly", elapsedMillis < 5_000);
        assertEquals("previous-good-output\n",
                Files.readString(output, StandardCharsets.UTF_8));
        assertNoTemporaryOutput(root);
    }

    @Test
    public void derivesPredictableSidecarOutputName() {
        Path withExtension = Path.of("logs", "crash.txt");
        Path withoutExtension = Path.of("logs", "crash");
        assertEquals(Path.of("logs", "crash.retraced.txt"),
                AndroidRetraceRunner.defaultOutput(withExtension));
        assertEquals(Path.of("logs", "crash.retraced.txt"),
                AndroidRetraceRunner.defaultOutput(withoutExtension));
    }

    private static Path executable(Path path, String source) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, source, StandardCharsets.UTF_8);
        if (!path.toFile().setExecutable(true, true) && !Files.isExecutable(path)) {
            throw new IOException("cannot mark test fixture executable: " + path);
        }
        return path;
    }

    private static void assertNoTemporaryOutput(Path directory) throws IOException {
        try (java.util.stream.Stream<Path> files = Files.list(directory)) {
            assertFalse(files.anyMatch(path -> path.getFileName().toString()
                    .startsWith(".dexcfg-retrace-")));
        }
    }
}
