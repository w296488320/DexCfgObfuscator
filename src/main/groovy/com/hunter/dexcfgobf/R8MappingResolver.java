package com.hunter.dexcfgobf;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** 把 R8 mapping 左侧原始业务类名解析成最终 DEX 中的精确类名白名单。 */
public final class R8MappingResolver {

    public static int apply(File mapping, ObfuscatorConfig config) throws IOException {
        if (mapping == null || !mapping.isFile()) {
            throw new IOException("R8 mapping is not a file: " + mapping);
        }
        config.resolvedIncludeClasses.clear();
        try (BufferedReader reader = Files.newBufferedReader(mapping.toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                // member mapping 行带缩进；注释/空行也不属于 class mapping。
                if (line.isEmpty() || Character.isWhitespace(line.charAt(0)) || line.charAt(0) == '#') {
                    continue;
                }
                int arrow = line.indexOf(" -> ");
                if (arrow <= 0 || !line.endsWith(":")) {
                    continue;
                }
                String original = line.substring(0, arrow);
                String renamed = line.substring(arrow + 4, line.length() - 1);
                if (config.shouldProcessOriginalClass(original)) {
                    config.resolvedIncludeClasses.add(ObfuscatorConfig.normalizeClassName(renamed));
                }
            }
        }
        config.requireResolvedIncludeClasses = true;
        return config.resolvedIncludeClasses.size();
    }

    private R8MappingResolver() {}
}
