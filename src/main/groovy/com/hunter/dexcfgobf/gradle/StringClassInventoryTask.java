package com.hunter.dexcfgobf.gradle;

import com.hunter.dexcfgobf.ObfuscatorConfig;
import com.hunter.dexcfgobf.string.StringClassConstantPoolCompactor;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.Directory;
import org.gradle.api.file.RegularFile;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Materializes the official AGP scoped-classes owner inventory for incremental evidence repair. */
@CacheableTask
public abstract class StringClassInventoryTask extends DefaultTask {
    @Classpath
    public abstract ListProperty<RegularFile> getInputJars();

    @Classpath
    public abstract ListProperty<Directory> getInputDirectories();

    @OutputFile
    public abstract RegularFileProperty getOwnerInventoryFile();

    @TaskAction
    public void inventoryOwners() throws IOException {
        List<File> roots = new ArrayList<>();
        for (RegularFile jar : getInputJars().get()) roots.add(jar.getAsFile());
        for (Directory directory : getInputDirectories().get()) {
            roots.add(directory.getAsFile());
        }
        Set<String> owners = StringClassConstantPoolCompactor.scanClassOwners(roots);
        File output = getOwnerInventoryFile().get().getAsFile();
        File parent = output.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new IOException("cannot create string class inventory directory");
        }
        Files.write(output.toPath(), owners, StandardCharsets.UTF_8);
    }

    public static Set<String> readOwners(File inventoryFile) throws IOException {
        if (inventoryFile == null || !inventoryFile.isFile()) {
            throw new IOException("string class owner inventory is missing");
        }
        TreeSet<String> owners = new TreeSet<>();
        for (String raw : Files.readAllLines(inventoryFile.toPath(), StandardCharsets.UTF_8)) {
            String owner = ObfuscatorConfig.normalizeClassName(raw);
            if (owner.isEmpty() || owner.startsWith("/") || owner.endsWith("/")
                    || owner.contains("//")) {
                throw new IOException("string class owner inventory is invalid");
            }
            owners.add(owner);
        }
        if (owners.isEmpty()) throw new IOException("string class owner inventory is empty");
        return Collections.unmodifiableSet(owners);
    }
}
