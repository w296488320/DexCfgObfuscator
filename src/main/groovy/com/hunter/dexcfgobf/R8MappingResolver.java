package com.hunter.dexcfgobf;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** 把 R8 mapping 左侧原始业务类名解析成最终 DEX 中的精确类名白名单。 */
public final class R8MappingResolver {

    public static int apply(File mapping, ObfuscatorConfig config) throws IOException {
        Objects.requireNonNull(config, "config");
        ParsedMapping parsed = parseMapping(mapping);
        Map<String, String> classMappings = parsed.classMappings;
        Map<String, Set<String>> originalsByFinalOwner = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : classMappings.entrySet()) {
            originalsByFinalOwner.computeIfAbsent(entry.getValue(), ignored ->
                    new LinkedHashSet<>()).add(entry.getKey());
        }
        Set<String> classWide = new LinkedHashSet<>();
        for (Map.Entry<String, String> entry : classMappings.entrySet()) {
            if (config.shouldProcessOriginalClass(entry.getKey())) {
                classWide.add(entry.getValue());
            }
        }
        // A final owner shared with any non-target class is not safe for class-wide processing.
        classWide.removeIf(finalOwner -> originalsByFinalOwner.get(finalOwner).stream()
                .anyMatch(original -> !config.shouldProcessOriginalClass(original)));

        Set<String> resolvedMethods = new LinkedHashSet<>();
        addResolvedMemberMethods(config, parsed.methodMappings, resolvedMethods);
        Set<String> resolved = new LinkedHashSet<>(classWide);
        for (String method : resolvedMethods) {
            resolved.add(method.substring(0, method.indexOf("->")));
        }

        // 解析与匹配全部成功后再切换 config，避免坏 mapping 留下部分状态。
        config.resolvedIncludeClasses.clear();
        config.resolvedIncludeClasses.addAll(resolved);
        config.resolvedClassWideIncludeClasses.clear();
        config.resolvedClassWideIncludeClasses.addAll(classWide);
        config.resolvedIncludeMethods.clear();
        config.resolvedIncludeMethods.addAll(resolvedMethods);
        config.requireResolvedIncludeClasses = true;
        return resolved.size();
    }

    private static void addResolvedMemberMethods(
            ObfuscatorConfig config,
            Map<String, Set<FinalMember>> memberMappings,
            Set<String> resolvedMethods) {
        for (Map.Entry<String, Set<FinalMember>> entry : memberMappings.entrySet()) {
            int arrow = entry.getKey().indexOf("->");
            if (arrow <= 0 || !config.shouldProcessOriginalClass(
                    entry.getKey().substring(0, arrow))) {
                continue;
            }
            for (FinalMember target : entry.getValue()) {
                resolvedMethods.add(target.ownerInternalName + "->" + target.memberName);
            }
        }
    }

    /**
     * 精确解析一组 R8 左侧原始 owner。请求会规范化为不带 {@code L;}
     * 的 JVM internal name，并按首次出现去重；不做前缀匹配。
     */
    public static ExactOwnerResolution resolveExactOwners(
            File mapping,
            Collection<String> requestedOriginalOwners) throws IOException {
        Objects.requireNonNull(requestedOriginalOwners, "requestedOriginalOwners");

        Set<String> requested = new LinkedHashSet<>();
        int requestedIndex = 0;
        for (String owner : requestedOriginalOwners) {
            requestedIndex++;
            requested.add(normalizeAndValidateClassName(owner,
                    "requested original owner at index " + requestedIndex));
        }

        Map<String, String> classMappings = parseMapping(mapping).classMappings;
        Map<String, String> resolved = new LinkedHashMap<>();
        Set<String> missing = new LinkedHashSet<>();
        for (String owner : requested) {
            String finalOwner = classMappings.get(owner);
            if (finalOwner == null) {
                missing.add(owner);
            } else {
                resolved.put(owner, finalOwner);
            }
        }
        return new ExactOwnerResolution(requested, resolved, missing);
    }

    /**
     * 精确解析原始方法/字段关系。方法 key 必须为
     * {@code ownerInternal->name(descriptor)}，字段 key 必须为
     * {@code ownerInternal->name}。R8 可以把原始成员合并或内联到另一个 class header，
     * 因此原始 owner 从 member 左侧的全限定名优先提取，final owner 则始终取
     * 当前 class header 右侧。
     *
     * <p>final descriptor 不在结果中：R8 prototype rewrite 后只依赖普通 mapping
     * member 行不能对所有情形可靠恢复 residual descriptor。</p>
     */
    public static ExactMemberResolution resolveExactMembers(
            File mapping,
            Collection<String> requestedOriginalMethodKeys,
            Collection<String> requestedOriginalFieldKeys) throws IOException {
        Set<String> requestedMethods = normalizeRequestedMemberKeys(
                requestedOriginalMethodKeys, true);
        Set<String> requestedFields = normalizeRequestedMemberKeys(
                requestedOriginalFieldKeys, false);
        ParsedMapping parsed = parseMapping(mapping);

        Map<String, Set<FinalMember>> resolvedMethods = new LinkedHashMap<>();
        Set<String> missingMethods = new LinkedHashSet<>();
        Map<String, Set<FinalMember>> conflictingMethods = new LinkedHashMap<>();
        resolveMemberRelations(requestedMethods, parsed.methodMappings,
                resolvedMethods, missingMethods, conflictingMethods);

        Map<String, Set<FinalMember>> resolvedFields = new LinkedHashMap<>();
        Set<String> missingFields = new LinkedHashSet<>();
        Map<String, Set<FinalMember>> conflictingFields = new LinkedHashMap<>();
        resolveMemberRelations(requestedFields, parsed.fieldMappings,
                resolvedFields, missingFields, conflictingFields);

        return new ExactMemberResolution(
                requestedMethods, requestedFields,
                resolvedMethods, resolvedFields,
                missingMethods, missingFields,
                conflictingMethods, conflictingFields);
    }

    /**
     * Reads R8's optional {@code usage.txt}/{@code seeds.txt} companions next to mapping.txt.
     * Missing reports are deliberately represented as unavailable instead of as an empty proof:
     * callers must keep their fail-closed fallback for every unclassified member.
     *
     * <p>The parser only retains exact relations for the requested members. A class-only usage
     * line proves that every requested member of that original owner was removed; a class header
     * followed by indented member lines proves only those exact members. Seed field descriptors
     * are retained because final-Dex identity candidates must be checked by owner, name and type,
     * not by a same-name guess.</p>
     */
    public static ShrinkerCompanionReports readCompanionReports(
            File mapping,
            Collection<String> requestedOriginalMethodKeys,
            Collection<String> requestedOriginalFieldKeys) throws IOException {
        if (mapping == null || !mapping.isFile()) {
            throw new IOException("R8 mapping is not a file: " + mapping);
        }
        Set<String> requestedMethods = normalizeRequestedMemberKeys(
                requestedOriginalMethodKeys, true);
        Set<String> requestedFields = normalizeRequestedMemberKeys(
                requestedOriginalFieldKeys, false);
        Set<String> requestedOwners = new LinkedHashSet<>();
        for (String key : requestedMethods) requestedOwners.add(memberOwner(key));
        for (String key : requestedFields) requestedOwners.add(memberOwner(key));

        File directory = mapping.getAbsoluteFile().getParentFile();
        File usage = new File(directory, "usage.txt");
        File seeds = new File(directory, "seeds.txt");
        CompanionAccumulator result = new CompanionAccumulator(
                usage.isFile(), seeds.isFile());
        if (result.usageAvailable) {
            parseUsageReport(usage, requestedOwners, requestedMethods, requestedFields, result);
        }
        if (result.seedsAvailable) {
            parseSeedsReport(seeds, requestedOwners, requestedMethods, requestedFields, result);
        }
        return result.freeze();
    }

    private static void parseUsageReport(
            File usage,
            Set<String> requestedOwners,
            Set<String> requestedMethods,
            Set<String> requestedFields,
            CompanionAccumulator result) throws IOException {
        String currentOwner = null;
        try (BufferedReader reader = Files.newBufferedReader(
                usage.toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.charAt(0) == '#') continue;
                if (!Character.isWhitespace(line.charAt(0))) {
                    boolean memberBlock = trimmed.endsWith(":");
                    String rawOwner = memberBlock
                            ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
                    currentOwner = requestedReportOwner(rawOwner, requestedOwners);
                    if (!memberBlock && currentOwner != null) {
                        result.removedClasses.add(currentOwner);
                    }
                    continue;
                }
                if (currentOwner == null) continue;
                ReportMember member = parseReportMember(currentOwner, trimmed);
                if (member == null) continue;
                if (member.method && requestedMethods.contains(member.key)) {
                    result.removedMethods.add(member.key);
                } else if (!member.method && requestedFields.contains(member.key)
                        && "Ljava/lang/String;".equals(member.descriptor)) {
                    result.removedFields.add(member.key);
                }
            }
        }
    }

    private static void parseSeedsReport(
            File seeds,
            Set<String> requestedOwners,
            Set<String> requestedMethods,
            Set<String> requestedFields,
            CompanionAccumulator result) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(
                seeds.toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.charAt(0) == '#') continue;
                int separator = trimmed.indexOf(": ");
                if (separator < 0) {
                    String owner = requestedReportOwner(trimmed, requestedOwners);
                    if (owner != null) result.seededClasses.add(owner);
                    continue;
                }
                String owner = requestedReportOwner(
                        trimmed.substring(0, separator), requestedOwners);
                if (owner == null) continue;
                ReportMember member = parseReportMember(
                        owner, trimmed.substring(separator + 2).trim());
                if (member == null) continue;
                if (member.method && requestedMethods.contains(member.key)) {
                    result.seededMethods.add(member.key);
                } else if (!member.method && requestedFields.contains(member.key)
                        && "Ljava/lang/String;".equals(member.descriptor)) {
                    result.seededFieldDescriptors.computeIfAbsent(member.key,
                            ignored -> new LinkedHashSet<>()).add(member.descriptor);
                }
            }
        }
    }

    private static String requestedReportOwner(String raw, Set<String> requestedOwners) {
        if (raw == null || raw.isEmpty()) return null;
        String candidate = raw.replace('.', '/');
        if (!requestedOwners.contains(candidate)) return null;
        try {
            return normalizeAndValidateClassName(raw, "R8 usage/seeds owner");
        } catch (IllegalArgumentException ignored) {
            // An unparseable line is not removal/identity proof. The caller remains fail-closed.
            return null;
        }
    }

    private static ReportMember parseReportMember(String owner, String signature) {
        if (signature == null || signature.isEmpty()) return null;
        try {
            int open = signature.indexOf('(');
            if (open >= 0) {
                int close = signature.indexOf(')', open + 1);
                if (close < open || close != signature.length() - 1
                        || signature.indexOf('(', open + 1) >= 0) {
                    return null;
                }
                String head = signature.substring(0, open).trim();
                int nameSeparator = lastWhitespace(head);
                if (nameSeparator <= 0) return null;
                String name = head.substring(nameSeparator + 1);
                String beforeName = head.substring(0, nameSeparator).trim();
                int returnSeparator = lastWhitespace(beforeName);
                String returnType = returnSeparator < 0
                        ? beforeName : beforeName.substring(returnSeparator + 1);
                if (!isValidMemberName(name)) return null;
                String descriptor = methodDescriptor(
                        signature.substring(open + 1, close), returnType,
                        "R8 usage/seeds method");
                return new ReportMember(owner + "->" + name + descriptor,
                        descriptor, true);
            }
            int nameSeparator = lastWhitespace(signature);
            if (nameSeparator <= 0) return null;
            String name = signature.substring(nameSeparator + 1);
            String beforeName = signature.substring(0, nameSeparator).trim();
            int typeSeparator = lastWhitespace(beforeName);
            String fieldType = typeSeparator < 0
                    ? beforeName : beforeName.substring(typeSeparator + 1);
            if (!isValidMemberName(name)) return null;
            String descriptor = javaTypeDescriptor(
                    fieldType, false, "R8 usage/seeds field");
            return new ReportMember(owner + "->" + name, descriptor, false);
        } catch (IllegalArgumentException ignored) {
            // Unsupported report syntax cannot be used as proof; leave the member unknown.
            return null;
        }
    }

    private static int lastWhitespace(String value) {
        for (int index = value.length() - 1; index >= 0; index--) {
            if (Character.isWhitespace(value.charAt(index))) return index;
        }
        return -1;
    }

    private static String memberOwner(String key) {
        return key.substring(0, key.indexOf("->"));
    }

    private static ParsedMapping parseMapping(File mapping) throws IOException {
        if (mapping == null || !mapping.isFile()) {
            throw new IOException("R8 mapping is not a file: " + mapping);
        }

        ParsedMapping parsed = new ParsedMapping();
        String currentOriginalOwner = null;
        String currentFinalOwner = null;
        try (BufferedReader reader = Files.newBufferedReader(mapping.toPath(), StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.charAt(0) == '#') {
                    continue;
                }
                if (Character.isWhitespace(line.charAt(0))) {
                    if (currentOriginalOwner == null || currentFinalOwner == null) {
                        throw invalidMemberMapping(mapping, lineNumber);
                    }
                    parseMemberMapping(trimmed, currentOriginalOwner, currentFinalOwner,
                            mapping, lineNumber, parsed);
                    continue;
                }

                int arrow = line.indexOf(" -> ");
                if (arrow <= 0 || line.indexOf(" -> ", arrow + 4) >= 0 || !line.endsWith(":")) {
                    throw invalidClassMapping(mapping, lineNumber);
                }
                String original = line.substring(0, arrow);
                String renamed = line.substring(arrow + 4, line.length() - 1);
                if (!original.equals(original.trim()) || !renamed.equals(renamed.trim())) {
                    throw invalidClassMapping(mapping, lineNumber);
                }
                String originalInternal;
                String finalInternal;
                try {
                    originalInternal = normalizeAndValidateClassName(
                            original, "original class at " + mapping + ":" + lineNumber);
                    finalInternal = normalizeAndValidateClassName(
                            renamed, "final class at " + mapping + ":" + lineNumber);
                } catch (IllegalArgumentException invalidName) {
                    IOException failure = invalidClassMapping(mapping, lineNumber);
                    failure.initCause(invalidName);
                    throw failure;
                }
                String previous = parsed.classMappings.putIfAbsent(originalInternal, finalInternal);
                if (previous != null && !previous.equals(finalInternal)) {
                    throw new IOException("Conflicting R8 class mappings for original owner "
                            + originalInternal + " at " + mapping + ":" + lineNumber);
                }
                currentOriginalOwner = originalInternal;
                currentFinalOwner = finalInternal;
            }
        }
        return parsed;
    }

    private static void parseMemberMapping(
            String line,
            String currentOriginalOwner,
            String currentFinalOwner,
            File mapping,
            int lineNumber,
            ParsedMapping parsed) throws IOException {
        int arrow = line.indexOf(" -> ");
        if (arrow <= 0 || line.indexOf(" -> ", arrow + 4) >= 0) {
            throw invalidMemberMapping(mapping, lineNumber);
        }
        String left = line.substring(0, arrow);
        String finalName = line.substring(arrow + 4);
        if (!left.equals(left.trim()) || !finalName.equals(finalName.trim())
                || !isValidMemberName(finalName)) {
            throw invalidMemberMapping(mapping, lineNumber);
        }

        String signature = stripOptionalObfuscatedLineRange(left);
        int open = signature.indexOf('(');
        if (open >= 0) {
            parseMethodMapping(signature, open, finalName, currentOriginalOwner,
                    currentFinalOwner, mapping, lineNumber, parsed);
        } else {
            parseFieldMapping(signature, finalName, currentOriginalOwner,
                    currentFinalOwner, mapping, lineNumber, parsed);
        }
    }

    private static void parseMethodMapping(
            String signature,
            int open,
            String finalName,
            String currentOriginalOwner,
            String currentFinalOwner,
            File mapping,
            int lineNumber,
            ParsedMapping parsed) throws IOException {
        int close = signature.indexOf(')', open + 1);
        if (open <= 0 || close <= open || signature.indexOf('(', open + 1) >= 0
                || signature.indexOf(')', close + 1) >= 0
                || !isValidOriginalLineSuffix(signature.substring(close + 1))) {
            throw invalidMemberMapping(mapping, lineNumber);
        }

        String head = signature.substring(0, open);
        int separator = firstWhitespace(head);
        if (separator <= 0) {
            throw invalidMemberMapping(mapping, lineNumber);
        }
        String returnType = head.substring(0, separator);
        String qualifiedName = head.substring(skipWhitespace(head, separator));
        if (qualifiedName.isEmpty() || containsWhitespace(qualifiedName)) {
            throw invalidMemberMapping(mapping, lineNumber);
        }

        SourceMember source = sourceMember(
                qualifiedName, currentOriginalOwner, mapping, lineNumber);
        String descriptor;
        try {
            descriptor = methodDescriptor(
                    signature.substring(open + 1, close), returnType,
                    "method at " + mapping + ":" + lineNumber);
        } catch (IllegalArgumentException invalidDescriptor) {
            IOException failure = invalidMemberMapping(mapping, lineNumber);
            failure.initCause(invalidDescriptor);
            throw failure;
        }
        String originalKey = source.owner + "->" + source.name + descriptor;
        addMemberRelation(parsed.methodMappings, originalKey,
                new FinalMember(currentFinalOwner, finalName));
    }

    private static void parseFieldMapping(
            String signature,
            String finalName,
            String currentOriginalOwner,
            String currentFinalOwner,
            File mapping,
            int lineNumber,
            ParsedMapping parsed) throws IOException {
        if (signature.indexOf(')') >= 0) {
            throw invalidMemberMapping(mapping, lineNumber);
        }
        int separator = firstWhitespace(signature);
        if (separator <= 0) {
            throw invalidMemberMapping(mapping, lineNumber);
        }
        String fieldType = signature.substring(0, separator);
        String qualifiedName = signature.substring(skipWhitespace(signature, separator));
        if (qualifiedName.isEmpty() || containsWhitespace(qualifiedName)) {
            throw invalidMemberMapping(mapping, lineNumber);
        }
        try {
            javaTypeDescriptor(fieldType, false,
                    "field at " + mapping + ":" + lineNumber);
        } catch (IllegalArgumentException invalidDescriptor) {
            IOException failure = invalidMemberMapping(mapping, lineNumber);
            failure.initCause(invalidDescriptor);
            throw failure;
        }
        SourceMember source = sourceMember(
                qualifiedName, currentOriginalOwner, mapping, lineNumber);
        String originalKey = source.owner + "->" + source.name;
        addMemberRelation(parsed.fieldMappings, originalKey,
                new FinalMember(currentFinalOwner, finalName));
    }

    private static SourceMember sourceMember(
            String qualifiedName,
            String currentOriginalOwner,
            File mapping,
            int lineNumber) throws IOException {
        int dot = qualifiedName.lastIndexOf('.');
        int slash = qualifiedName.lastIndexOf('/');
        int separator = Math.max(dot, slash);
        String owner = currentOriginalOwner;
        String name = qualifiedName;
        if (separator >= 0) {
            if (separator == 0 || separator == qualifiedName.length() - 1) {
                throw invalidMemberMapping(mapping, lineNumber);
            }
            try {
                owner = normalizeAndValidateClassName(
                        qualifiedName.substring(0, separator),
                        "member owner at " + mapping + ":" + lineNumber);
            } catch (IllegalArgumentException invalidOwner) {
                IOException failure = invalidMemberMapping(mapping, lineNumber);
                failure.initCause(invalidOwner);
                throw failure;
            }
            name = qualifiedName.substring(separator + 1);
        }
        if (!isValidMemberName(name)) {
            throw invalidMemberMapping(mapping, lineNumber);
        }
        return new SourceMember(owner, name);
    }

    private static String stripOptionalObfuscatedLineRange(String value) {
        int first = value.indexOf(':');
        if (first <= 0 || !isUnsignedInteger(value, 0, first)) {
            return value;
        }
        int second = value.indexOf(':', first + 1);
        if (second <= first + 1 || !isUnsignedInteger(value, first + 1, second)) {
            return value;
        }
        return value.substring(second + 1);
    }

    private static boolean isValidOriginalLineSuffix(String suffix) {
        if (suffix.isEmpty()) {
            return true;
        }
        if (suffix.charAt(0) != ':') {
            return false;
        }
        int start = 1;
        int segments = 0;
        while (start <= suffix.length()) {
            int end = suffix.indexOf(':', start);
            if (end < 0) {
                end = suffix.length();
            }
            if (!isUnsignedInteger(suffix, start, end)) {
                return false;
            }
            segments++;
            if (end == suffix.length()) {
                break;
            }
            start = end + 1;
        }
        return segments == 1 || segments == 2;
    }

    private static boolean isUnsignedInteger(String value, int start, int end) {
        if (start >= end) {
            return false;
        }
        for (int i = start; i < end; i++) {
            if (value.charAt(i) < '0' || value.charAt(i) > '9') {
                return false;
            }
        }
        return true;
    }

    private static int firstWhitespace(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isWhitespace(value.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    private static int skipWhitespace(String value, int start) {
        int index = start;
        while (index < value.length() && Character.isWhitespace(value.charAt(index))) {
            index++;
        }
        return index;
    }

    private static boolean containsWhitespace(String value) {
        return firstWhitespace(value) >= 0;
    }

    private static boolean isValidMemberName(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '.' || c == '/' || c == ';' || c == '[' || c == ':'
                    || c == '(' || c == ')' || Character.isWhitespace(c)
                    || Character.isISOControl(c)) {
                return false;
            }
        }
        return true;
    }

    private static String methodDescriptor(
            String arguments,
            String returnType,
            String location) {
        StringBuilder descriptor = new StringBuilder("(");
        if (!arguments.trim().isEmpty()) {
            String[] types = arguments.split(",", -1);
            for (String type : types) {
                String trimmed = type.trim();
                if (trimmed.isEmpty()) {
                    throw new IllegalArgumentException("Invalid method arguments: " + location);
                }
                descriptor.append(javaTypeDescriptor(trimmed, false, location));
            }
        }
        descriptor.append(')');
        descriptor.append(javaTypeDescriptor(returnType, true, location));
        return descriptor.toString();
    }

    private static String javaTypeDescriptor(
            String javaType,
            boolean allowVoid,
            String location) {
        if (javaType == null || javaType.isEmpty() || !javaType.equals(javaType.trim())
                || containsWhitespace(javaType)) {
            throw new IllegalArgumentException("Invalid Java type: " + location);
        }
        int dimensions = 0;
        String base = javaType;
        while (base.endsWith("[]")) {
            dimensions++;
            base = base.substring(0, base.length() - 2);
        }
        if (base.isEmpty() || (dimensions > 0 && "void".equals(base))) {
            throw new IllegalArgumentException("Invalid Java type: " + location);
        }

        String descriptor;
        switch (base) {
            case "void":
                if (!allowVoid) {
                    throw new IllegalArgumentException("void is not valid here: " + location);
                }
                descriptor = "V";
                break;
            case "boolean": descriptor = "Z"; break;
            case "byte": descriptor = "B"; break;
            case "char": descriptor = "C"; break;
            case "short": descriptor = "S"; break;
            case "int": descriptor = "I"; break;
            case "long": descriptor = "J"; break;
            case "float": descriptor = "F"; break;
            case "double": descriptor = "D"; break;
            default:
                descriptor = "L" + normalizeAndValidateClassName(base, location) + ";";
                break;
        }
        StringBuilder result = new StringBuilder(dimensions + descriptor.length());
        for (int i = 0; i < dimensions; i++) {
            result.append('[');
        }
        return result.append(descriptor).toString();
    }

    private static Set<String> normalizeRequestedMemberKeys(
            Collection<String> requestedKeys,
            boolean method) {
        Objects.requireNonNull(requestedKeys,
                method ? "requestedOriginalMethodKeys" : "requestedOriginalFieldKeys");
        Set<String> normalized = new LinkedHashSet<>();
        int index = 0;
        for (String key : requestedKeys) {
            index++;
            normalized.add(normalizeRequestedMemberKey(key, method, index));
        }
        return normalized;
    }

    private static String normalizeRequestedMemberKey(
            String key,
            boolean method,
            int index) {
        String label = (method ? "method" : "field") + " key at index " + index;
        if (key == null || !key.equals(key.trim())) {
            throw new IllegalArgumentException("Invalid original " + label);
        }
        int arrow = key.indexOf("->");
        if (arrow <= 0 || key.indexOf("->", arrow + 2) >= 0) {
            throw new IllegalArgumentException("Invalid original " + label);
        }
        String owner = normalizeAndValidateClassName(key.substring(0, arrow), label);
        String member = key.substring(arrow + 2);
        if (method) {
            int open = member.indexOf('(');
            if (open <= 0 || !isValidMemberName(member.substring(0, open))) {
                throw new IllegalArgumentException("Invalid original " + label);
            }
            validateMethodDescriptor(member.substring(open), label);
        } else if (!isValidMemberName(member)) {
            throw new IllegalArgumentException("Invalid original " + label);
        }
        return owner + "->" + member;
    }

    private static void validateMethodDescriptor(String descriptor, String location) {
        if (descriptor.isEmpty() || descriptor.charAt(0) != '(') {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
        int index = 1;
        while (index < descriptor.length() && descriptor.charAt(index) != ')') {
            index = descriptorTypeEnd(descriptor, index, false, location);
        }
        if (index >= descriptor.length() || descriptor.charAt(index) != ')') {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
        index = descriptorTypeEnd(descriptor, index + 1, true, location);
        if (index != descriptor.length()) {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
    }

    private static int descriptorTypeEnd(
            String descriptor,
            int start,
            boolean allowVoid,
            String location) {
        int index = start;
        while (index < descriptor.length() && descriptor.charAt(index) == '[') {
            index++;
        }
        boolean array = index > start;
        if (index >= descriptor.length()) {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
        char type = descriptor.charAt(index);
        if (type == 'V') {
            if (!allowVoid || array) {
                throw new IllegalArgumentException("Invalid method descriptor: " + location);
            }
            return index + 1;
        }
        if (type == 'Z' || type == 'B' || type == 'C' || type == 'S'
                || type == 'I' || type == 'J' || type == 'F' || type == 'D') {
            return index + 1;
        }
        if (type != 'L') {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
        int end = descriptor.indexOf(';', index + 1);
        if (end <= index + 1) {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
        String internalName = descriptor.substring(index + 1, end);
        if (internalName.indexOf('.') >= 0) {
            throw new IllegalArgumentException("Invalid method descriptor: " + location);
        }
        normalizeAndValidateClassName(internalName, location);
        return end + 1;
    }

    private static void addMemberRelation(
            Map<String, Set<FinalMember>> relations,
            String originalKey,
            FinalMember target) {
        relations.computeIfAbsent(originalKey, ignored -> new LinkedHashSet<>()).add(target);
    }

    private static void resolveMemberRelations(
            Set<String> requested,
            Map<String, Set<FinalMember>> available,
            Map<String, Set<FinalMember>> resolved,
            Set<String> missing,
            Map<String, Set<FinalMember>> conflicting) {
        for (String key : requested) {
            Set<FinalMember> targets = available.get(key);
            if (targets == null || targets.isEmpty()) {
                missing.add(key);
            } else {
                // R8 inline-frame mappings legitimately map one original method to several
                // containing final methods. Preserve every target; ordinary mapping syntax does
                // not provide enough information to call distinct sites contradictory.
                resolved.put(key, new LinkedHashSet<>(targets));
            }
        }
    }

    private static String normalizeAndValidateClassName(String className, String location) {
        if (className == null) {
            throw new IllegalArgumentException("Null R8 class name: " + location);
        }
        if (!className.equals(className.trim())) {
            throw new IllegalArgumentException("R8 class name has surrounding whitespace: " + location);
        }
        String normalized = ObfuscatorConfig.normalizeClassName(className);
        if (normalized.isEmpty() || normalized.startsWith("/") || normalized.endsWith("/")
                || normalized.contains("//")) {
            throw new IllegalArgumentException("Invalid R8 class name: " + location);
        }
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (c == ';' || c == '[' || c == ':' || c == '\\'
                    || Character.isWhitespace(c) || Character.isISOControl(c)) {
                throw new IllegalArgumentException("Invalid R8 class name: " + location);
            }
        }
        return normalized;
    }

    private static IOException invalidClassMapping(File mapping, int lineNumber) {
        return new IOException("Invalid R8 class mapping at " + mapping + ":" + lineNumber);
    }

    private static IOException invalidMemberMapping(File mapping, int lineNumber) {
        return new IOException("Invalid R8 member mapping at " + mapping + ":" + lineNumber);
    }

    private static final class ParsedMapping {
        final Map<String, String> classMappings = new LinkedHashMap<>();
        final Map<String, Set<FinalMember>> methodMappings = new LinkedHashMap<>();
        final Map<String, Set<FinalMember>> fieldMappings = new LinkedHashMap<>();
    }

    private static final class SourceMember {
        final String owner;
        final String name;

        SourceMember(String owner, String name) {
            this.owner = owner;
            this.name = name;
        }
    }

    private static final class ReportMember {
        final String key;
        final String descriptor;
        final boolean method;

        ReportMember(String key, String descriptor, boolean method) {
            this.key = key;
            this.descriptor = descriptor;
            this.method = method;
        }
    }

    private static final class CompanionAccumulator {
        final boolean usageAvailable;
        final boolean seedsAvailable;
        final Set<String> removedClasses = new LinkedHashSet<>();
        final Set<String> removedMethods = new LinkedHashSet<>();
        final Set<String> removedFields = new LinkedHashSet<>();
        final Set<String> seededClasses = new LinkedHashSet<>();
        final Set<String> seededMethods = new LinkedHashSet<>();
        final Map<String, Set<String>> seededFieldDescriptors = new LinkedHashMap<>();

        CompanionAccumulator(boolean usageAvailable, boolean seedsAvailable) {
            this.usageAvailable = usageAvailable;
            this.seedsAvailable = seedsAvailable;
        }

        ShrinkerCompanionReports freeze() {
            return new ShrinkerCompanionReports(usageAvailable, seedsAvailable,
                    removedClasses, removedMethods, removedFields, seededClasses,
                    seededMethods, seededFieldDescriptors);
        }
    }

    /** Immutable exact evidence parsed from mapping.txt's optional R8 companions. */
    public static final class ShrinkerCompanionReports {
        private final boolean usageAvailable;
        private final boolean seedsAvailable;
        private final Set<String> removedClasses;
        private final Set<String> removedMethods;
        private final Set<String> removedFields;
        private final Set<String> seededClasses;
        private final Set<String> seededMethods;
        private final Map<String, Set<String>> seededFieldDescriptors;

        private ShrinkerCompanionReports(
                boolean usageAvailable,
                boolean seedsAvailable,
                Set<String> removedClasses,
                Set<String> removedMethods,
                Set<String> removedFields,
                Set<String> seededClasses,
                Set<String> seededMethods,
                Map<String, Set<String>> seededFieldDescriptors) {
            this.usageAvailable = usageAvailable;
            this.seedsAvailable = seedsAvailable;
            this.removedClasses = immutableSet(removedClasses);
            this.removedMethods = immutableSet(removedMethods);
            this.removedFields = immutableSet(removedFields);
            this.seededClasses = immutableSet(seededClasses);
            this.seededMethods = immutableSet(seededMethods);
            this.seededFieldDescriptors = ExactMemberResolution.immutableRelationMap(
                    seededFieldDescriptors);
        }

        public boolean isUsageAvailable() {
            return usageAvailable;
        }

        public boolean isSeedsAvailable() {
            return seedsAvailable;
        }

        public boolean isMethodRemoved(String originalMethodKey) {
            return usageAvailable && (removedClasses.contains(memberOwner(originalMethodKey))
                    || removedMethods.contains(originalMethodKey));
        }

        public boolean isFieldRemoved(String originalFieldKey) {
            return usageAvailable && (removedClasses.contains(memberOwner(originalFieldKey))
                    || removedFields.contains(originalFieldKey));
        }

        /** True only for an exact class-only usage.txt removal line. */
        public boolean isClassRemoved(String originalOwner) {
            return usageAvailable && removedClasses.contains(originalOwner);
        }

        public boolean isMethodSeeded(String originalMethodKey) {
            return seedsAvailable && seededMethods.contains(originalMethodKey);
        }

        public Set<String> getSeededFieldDescriptors(String originalFieldKey) {
            Set<String> descriptors = seededFieldDescriptors.get(originalFieldKey);
            return descriptors == null ? Collections.emptySet() : descriptors;
        }

        public boolean isClassSeeded(String originalOwner) {
            return seedsAvailable && seededClasses.contains(originalOwner);
        }

        public int getRemovedClassCount() {
            return removedClasses.size();
        }

        public int getRemovedMethodCount() {
            return removedMethods.size();
        }

        public int getRemovedFieldCount() {
            return removedFields.size();
        }

        public int getSeededMethodCount() {
            return seededMethods.size();
        }

        public int getSeededFieldCount() {
            return seededFieldDescriptors.size();
        }

        private static <T> Set<T> immutableSet(Collection<T> source) {
            return Collections.unmodifiableSet(new LinkedHashSet<>(source));
        }
    }

    /** 一次 exact-owner 解析的不可变、防御性快照。 */
    public static final class ExactOwnerResolution {
        private final Set<String> requestedOwners;
        private final Map<String, String> resolvedOwners;
        private final Set<String> missingOwners;

        private ExactOwnerResolution(
                Set<String> requestedOwners,
                Map<String, String> resolvedOwners,
                Set<String> missingOwners) {
            this.requestedOwners = Collections.unmodifiableSet(
                    new LinkedHashSet<>(requestedOwners));
            this.resolvedOwners = Collections.unmodifiableMap(
                    new LinkedHashMap<>(resolvedOwners));
            this.missingOwners = Collections.unmodifiableSet(
                    new LinkedHashSet<>(missingOwners));
        }

        public int getRequestedCount() {
            return requestedOwners.size();
        }

        public int getResolvedCount() {
            return resolvedOwners.size();
        }

        public int getMissingCount() {
            return missingOwners.size();
        }

        public Set<String> getRequestedOwners() {
            return requestedOwners;
        }

        /** 返回 exact original internal name -&gt; final internal name。 */
        public Map<String, String> getResolvedOwners() {
            return resolvedOwners;
        }

        public Set<String> getMissingOwners() {
            return missingOwners;
        }
    }

    /** final owner + final member name；故意不声称包含 final descriptor。 */
    public static final class FinalMember {
        private final String ownerInternalName;
        private final String memberName;

        private FinalMember(String ownerInternalName, String memberName) {
            this.ownerInternalName = ownerInternalName;
            this.memberName = memberName;
        }

        public String getOwnerInternalName() {
            return ownerInternalName;
        }

        public String getMemberName() {
            return memberName;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof FinalMember)) return false;
            FinalMember that = (FinalMember) other;
            return ownerInternalName.equals(that.ownerInternalName)
                    && memberName.equals(that.memberName);
        }

        @Override
        public int hashCode() {
            return 31 * ownerInternalName.hashCode() + memberName.hashCode();
        }

        @Override
        public String toString() {
            return ownerInternalName + "->" + memberName;
        }
    }

    /** exact member relation 的不可变、防御性快照。 */
    public static final class ExactMemberResolution {
        private final Set<String> requestedMethods;
        private final Set<String> requestedFields;
        private final Map<String, Set<FinalMember>> resolvedMethods;
        private final Map<String, Set<FinalMember>> resolvedFields;
        private final Set<String> missingMethods;
        private final Set<String> missingFields;
        private final Map<String, Set<FinalMember>> conflictingMethods;
        private final Map<String, Set<FinalMember>> conflictingFields;
        private final Set<String> resolvedFinalOwners;

        private ExactMemberResolution(
                Set<String> requestedMethods,
                Set<String> requestedFields,
                Map<String, Set<FinalMember>> resolvedMethods,
                Map<String, Set<FinalMember>> resolvedFields,
                Set<String> missingMethods,
                Set<String> missingFields,
                Map<String, Set<FinalMember>> conflictingMethods,
                Map<String, Set<FinalMember>> conflictingFields) {
            this.requestedMethods = immutableSet(requestedMethods);
            this.requestedFields = immutableSet(requestedFields);
            this.resolvedMethods = immutableRelationMap(resolvedMethods);
            this.resolvedFields = immutableRelationMap(resolvedFields);
            this.missingMethods = immutableSet(missingMethods);
            this.missingFields = immutableSet(missingFields);
            this.conflictingMethods = immutableRelationMap(conflictingMethods);
            this.conflictingFields = immutableRelationMap(conflictingFields);

            Set<String> owners = new LinkedHashSet<>();
            for (Set<FinalMember> members : this.resolvedMethods.values()) {
                for (FinalMember member : members) owners.add(member.ownerInternalName);
            }
            for (Set<FinalMember> members : this.resolvedFields.values()) {
                for (FinalMember member : members) owners.add(member.ownerInternalName);
            }
            this.resolvedFinalOwners = immutableSet(owners);
        }

        public int getRequestedCount() {
            return requestedMethods.size() + requestedFields.size();
        }

        public int getResolvedCount() {
            return resolvedMethods.size() + resolvedFields.size();
        }

        public int getMissingCount() {
            return missingMethods.size() + missingFields.size();
        }

        public int getConflictCount() {
            return conflictingMethods.size() + conflictingFields.size();
        }

        public int getRequestedMethodCount() {
            return requestedMethods.size();
        }

        public int getRequestedFieldCount() {
            return requestedFields.size();
        }

        public int getResolvedMethodCount() {
            return resolvedMethods.size();
        }

        public int getResolvedFieldCount() {
            return resolvedFields.size();
        }

        public int getResolvedTargetCount() {
            int count = 0;
            for (Set<FinalMember> targets : resolvedMethods.values()) count += targets.size();
            for (Set<FinalMember> targets : resolvedFields.values()) count += targets.size();
            return count;
        }

        public int getMissingMethodCount() {
            return missingMethods.size();
        }

        public int getMissingFieldCount() {
            return missingFields.size();
        }

        public int getConflictingMethodCount() {
            return conflictingMethods.size();
        }

        public int getConflictingFieldCount() {
            return conflictingFields.size();
        }

        public Set<String> getRequestedMethods() {
            return requestedMethods;
        }

        public Set<String> getRequestedFields() {
            return requestedFields;
        }

        public Map<String, Set<FinalMember>> getResolvedMethods() {
            return resolvedMethods;
        }

        public Map<String, Set<FinalMember>> getResolvedFields() {
            return resolvedFields;
        }

        public Set<String> getMissingMethods() {
            return missingMethods;
        }

        public Set<String> getMissingFields() {
            return missingFields;
        }

        public Map<String, Set<FinalMember>> getConflictingMethods() {
            return conflictingMethods;
        }

        public Map<String, Set<FinalMember>> getConflictingFields() {
            return conflictingFields;
        }

        public Set<String> getResolvedFinalOwners() {
            return resolvedFinalOwners;
        }

        public boolean isComplete() {
            return getMissingCount() == 0 && getConflictCount() == 0
                    && getResolvedCount() == getRequestedCount();
        }

        private static <T> Set<T> immutableSet(Collection<T> source) {
            return Collections.unmodifiableSet(new LinkedHashSet<>(source));
        }

        private static <K, V> Map<K, V> immutableMap(Map<K, V> source) {
            return Collections.unmodifiableMap(new LinkedHashMap<>(source));
        }

        private static <K, V> Map<K, Set<V>> immutableRelationMap(
                Map<K, Set<V>> source) {
            Map<K, Set<V>> copy = new LinkedHashMap<>();
            for (Map.Entry<K, Set<V>> entry : source.entrySet()) {
                copy.put(entry.getKey(), immutableSet(entry.getValue()));
            }
            return Collections.unmodifiableMap(copy);
        }
    }

    private R8MappingResolver() {}
}
