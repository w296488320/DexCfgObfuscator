package com.hunter.dexcfgobf.gradle;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.options.Option;
import org.gradle.work.DisableCachingByDefault;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

/** Retraces a local crash stack-trace file with the matching variant's R8 mapping. */
@DisableCachingByDefault(because = "Processes a caller-supplied local crash stack trace")
public abstract class RetraceDexCfgStackTraceTask extends DefaultTask {

    @Internal
    public abstract RegularFileProperty getTraceFile();

    @Internal
    public abstract RegularFileProperty getOutputFile();

    @Internal
    public abstract RegularFileProperty getMappingFile();

    @Internal
    public abstract RegularFileProperty getRetraceExecutable();

    @Internal
    public abstract DirectoryProperty getAndroidSdkDirectory();

    @Input
    public abstract Property<Boolean> getMinified();

    public RetraceDexCfgStackTraceTask() {
        getMinified().convention(false);
    }

    @Option(option = "trace-file",
            description = "Local crash stack-trace file to retrace (required).")
    public void setTraceFileOption(String value) {
        getTraceFile().fileValue(optionFile(value, "--trace-file"));
    }

    @Option(option = "output-file",
            description = "Destination file; defaults to .retraced before the original "
                    + "extension (or appends .retraced.txt when there is no extension).")
    public void setOutputFileOption(String value) {
        getOutputFile().fileValue(optionFile(value, "--output-file"));
    }

    @Option(option = "mapping-file",
            description = "Archived mapping.txt from the exact minified release; overrides "
                    + "the current variant build output.")
    public void setMappingFileOption(String value) {
        getMappingFile().fileValue(optionFile(value, "--mapping-file"));
    }

    @TaskAction
    public void retrace() {
        if (!getTraceFile().isPresent()) {
            throw new GradleException("A local stack trace is required. Pass "
                    + "--trace-file=<path>.");
        }
        Path trace = getTraceFile().get().getAsFile().toPath();
        Path output = getOutputFile().isPresent()
                ? getOutputFile().get().getAsFile().toPath()
                : AndroidRetraceRunner.defaultOutput(trace);
        Path mapping = getMappingFile().isPresent()
                ? getMappingFile().get().getAsFile().toPath()
                : null;
        Path executable = getRetraceExecutable().isPresent()
                ? getRetraceExecutable().get().getAsFile().toPath()
                : null;
        Path sdkDirectory = getAndroidSdkDirectory().isPresent()
                ? getAndroidSdkDirectory().get().getAsFile().toPath()
                : null;
        try {
            AndroidRetraceRunner.Result result = AndroidRetraceRunner.run(
                    trace, output, mapping, getMinified().getOrElse(false), executable,
                    sdkDirectory);
            if (result == AndroidRetraceRunner.Result.RETRACED) {
                getLogger().lifecycle("[dex-cfg-obf] Retraced stack trace written to {}", output);
            } else {
                getLogger().lifecycle("[dex-cfg-obf] Variant is not minified; CFG-preserved "
                        + "stack trace copied unchanged to {}", output);
            }
        } catch (IOException | IllegalArgumentException failure) {
            throw new GradleException("Cannot retrace stack-trace file: "
                    + failure.getMessage(), failure);
        }
    }

    private File optionFile(String value, String option) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(option + " requires a non-empty path");
        }
        return getProject().file(value.trim());
    }
}
