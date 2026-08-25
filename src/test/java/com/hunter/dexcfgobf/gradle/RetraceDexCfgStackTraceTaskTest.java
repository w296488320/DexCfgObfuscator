package com.hunter.dexcfgobf.gradle;

import org.gradle.api.Project;
import org.gradle.api.tasks.options.Option;
import org.gradle.testfixtures.ProjectBuilder;
import org.gradle.work.DisableCachingByDefault;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class RetraceDexCfgStackTraceTaskTest {
    @Rule
    public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void exposesNonConflictingGradleOptions() {
        Set<String> options = Arrays.stream(RetraceDexCfgStackTraceTask.class.getMethods())
                .map(method -> method.getAnnotation(Option.class))
                .filter(annotation -> annotation != null)
                .map(Option::option)
                .collect(Collectors.toSet());

        assertEquals(Set.of("trace-file", "output-file", "mapping-file"), options);
        assertTrue("Gradle's global --stacktrace option must remain unshadowed",
                !options.contains("stacktrace"));
        assertNotNull(RetraceDexCfgStackTraceTask.class
                .getAnnotation(DisableCachingByDefault.class));
    }

    @Test
    public void taskPassesThroughNonMinifiedTraceToDefaultSidecar() throws Exception {
        Path projectDirectory = temporary.newFolder("consumer").toPath();
        Path trace = projectDirectory.resolve("crash.txt");
        Files.writeString(trace, "at sample.App.run(App.java:12)\n", StandardCharsets.UTF_8);
        Project project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build();
        RetraceDexCfgStackTraceTask task = project.getTasks().create(
                "retraceReleaseDexCfgStackTrace", RetraceDexCfgStackTraceTask.class);

        task.setTraceFileOption("crash.txt");
        task.getMinified().set(false);
        task.retrace();

        Path output = projectDirectory.resolve("crash.retraced.txt");
        assertEquals(Files.readString(trace, StandardCharsets.UTF_8),
                Files.readString(output, StandardCharsets.UTF_8));
    }

    @Test
    public void taskUsesConfiguredOfficialRetraceExecutableForMinifiedVariant() throws Exception {
        Path projectDirectory = temporary.newFolder("minified-consumer").toPath();
        Path trace = projectDirectory.resolve("crash.txt");
        Path mapping = projectDirectory.resolve("mapping.txt");
        Path output = projectDirectory.resolve("custom-result.txt");
        Path executable = projectDirectory.resolve("fake-retrace");
        Files.writeString(trace, "at a.a(SourceFile:1)\n", StandardCharsets.UTF_8);
        Files.writeString(mapping, "# mapping\n", StandardCharsets.UTF_8);
        Files.writeString(executable, "#!/bin/sh\nprintf 'retraced-by-sdk\\n'\ncat \"$2\"\n",
                StandardCharsets.UTF_8);
        assertTrue(executable.toFile().setExecutable(true, true) || Files.isExecutable(executable));
        Project project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build();
        RetraceDexCfgStackTraceTask task = project.getTasks().create(
                "retraceReleaseDexCfgStackTrace", RetraceDexCfgStackTraceTask.class);
        task.setTraceFileOption(trace.toString());
        task.setOutputFileOption(output.toString());
        task.setMappingFileOption(mapping.toString());
        task.getRetraceExecutable().fileValue(executable.toFile());
        task.getMinified().set(true);

        task.retrace();

        assertTrue(Files.readString(output, StandardCharsets.UTF_8)
                .startsWith("retraced-by-sdk\n"));
    }
}
