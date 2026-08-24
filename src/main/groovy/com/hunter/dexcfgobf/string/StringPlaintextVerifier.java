package com.hunter.dexcfgobf.string;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.reference.DexBackedStringReference;
import com.android.tools.smali.dexlib2.iface.Annotation;
import com.android.tools.smali.dexlib2.iface.AnnotationElement;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.CallSiteReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.iface.value.AnnotationEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.ArrayEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue;

import java.io.File;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * 对最终 DEX 中运行时可读取的字符串载荷做明文门禁。
 *
 * <p>默认硬门禁检查插桩实际选择过的 exact method 中的
 * {@code const-string}/{@code const-string-jumbo}，以及通用调用方提供的 exact field 静态
 * String encoded value。R8 无法精确映射的 site 可额外提供 global-runtime fallback hash；
 * 这些 hash 在任意运行时可读载荷（const-string、静态值、普通 annotation/default、call-site）
 * 中出现都会失败。平台结构名称不会触发 fallback。其他同值字符串仍会分类为
 * owner/global/whole-pool collision 诊断。调用方可显式启用 strict whole-pool 模式恢复
 * “任意字符串池同值都失败”语义。Seed-backed static String field identity candidates are
 * presence-checked separately by exact owner/name/descriptor; their executable hard gate remains
 * the exact {@code <clinit>()V} method supplied by the caller.</p>
 *
 * <p>所有比较仅在内存中使用 SHA-256；结果和错误信息都不包含业务明文或摘要。</p>
 */
public final class StringPlaintextVerifier {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private StringPlaintextVerifier() {}

    /** @deprecated Application verification requires an exact site-to-hash scope. */
    @Deprecated
    public static Result verifyDexDirectories(Collection<File> roots,
                                              Set<String> expectedPlaintextHashes)
            throws IOException {
        throw new IllegalArgumentException(
                "final DEX plaintext verification requires an exact target site scope");
    }

    /** @deprecated Application verification requires an exact site-to-hash scope. */
    @Deprecated
    public static Result verifyDexDirectories(Collection<File> roots,
                                              Set<String> expectedPlaintextHashes,
                                              boolean strictWholeStringPool)
            throws IOException {
        throw new IllegalArgumentException(
                "final DEX plaintext verification requires an exact target site scope");
    }

    public static Result verifyDexDirectories(
            Collection<File> roots,
            Set<String> expectedPlaintextHashes,
            Map<String, ? extends Set<String>> expectedHashesByTargetClass,
            Map<String, ? extends Set<String>> expectedHashesByTargetMethod,
            Map<String, ? extends Set<String>> expectedHashesByTargetField,
            boolean strictWholeStringPool) throws IOException {
        return verifyDexDirectories(roots, expectedPlaintextHashes,
                expectedHashesByTargetClass, expectedHashesByTargetMethod,
                expectedHashesByTargetField, Collections.emptySet(), strictWholeStringPool);
    }

    public static Result verifyDexDirectories(
            Collection<File> roots,
            Set<String> expectedPlaintextHashes,
            Map<String, ? extends Set<String>> expectedHashesByTargetClass,
            Map<String, ? extends Set<String>> expectedHashesByTargetMethod,
            Map<String, ? extends Set<String>> expectedHashesByTargetField,
            Set<String> globalRuntimeFallbackHashes,
            boolean strictWholeStringPool) throws IOException {
        return verifyDexDirectories(roots, expectedPlaintextHashes,
                expectedHashesByTargetClass, expectedHashesByTargetMethod,
                expectedHashesByTargetField, globalRuntimeFallbackHashes,
                Collections.emptySet(), Collections.emptySet(), strictWholeStringPool);
    }

    public static Result verifyDexDirectories(
            Collection<File> roots,
            Set<String> expectedPlaintextHashes,
            Map<String, ? extends Set<String>> expectedHashesByTargetClass,
            Map<String, ? extends Set<String>> expectedHashesByTargetMethod,
            Map<String, ? extends Set<String>> expectedHashesByTargetField,
            Set<String> globalRuntimeFallbackHashes,
            Set<String> removedOriginalSiteHashes,
            Set<String> identityFieldProvenanceTargets,
            boolean strictWholeStringPool) throws IOException {
        Set<String> expected = expectedPlaintextHashes == null
                ? Collections.emptySet() : new HashSet<>(expectedPlaintextHashes);
        Map<String, Set<String>> targets = normalizeTargetHashes(
                expectedHashesByTargetClass, expected);
        Map<String, Set<String>> targetMethods = normalizeTargetMemberHashes(
                expectedHashesByTargetMethod, expected, true);
        Map<String, Set<String>> targetFields = normalizeTargetMemberHashes(
                expectedHashesByTargetField, expected, false);
        Set<String> fallbackHashes = normalizeGlobalRuntimeFallbackHashes(
                globalRuntimeFallbackHashes, expected);
        Set<String> removedHashes = normalizeRemovedOriginalSiteHashes(
                removedOriginalSiteHashes, expected);
        Set<String> identityFields = normalizeIdentityFieldProvenanceTargets(
                identityFieldProvenanceTargets);
        if (expected.isEmpty()) {
            if (!targets.isEmpty() || !targetMethods.isEmpty() || !targetFields.isEmpty()
                    || !fallbackHashes.isEmpty() || !removedHashes.isEmpty()
                    || !identityFields.isEmpty()) {
                throw new IllegalArgumentException(
                        "empty plaintext scope contains non-empty target provenance");
            }
        } else if (targetMethods.isEmpty() && targetFields.isEmpty()
                && fallbackHashes.isEmpty() && removedHashes.isEmpty()) {
            throw new IllegalArgumentException(
                    "final DEX plaintext verification target site scope is empty; run a clean build");
        }
        List<File> dexFiles = new ArrayList<>();
        Set<String> canonicalFiles = new HashSet<>();
        if (roots != null) {
            for (File root : roots) collectDex(root, dexFiles, canonicalFiles);
        }
        dexFiles.sort(Comparator.comparing(File::getAbsolutePath));

        MutableResult result = new MutableResult(expected, targets, targetMethods, targetFields,
                fallbackHashes, removedHashes, identityFields);
        for (File dexFile : dexFiles) {
            DexBackedDexFile dex;
            try (BufferedInputStream input = new BufferedInputStream(
                    new FileInputStream(dexFile))) {
                dex = DexBackedDexFile.fromInputStream(null, input);
            }
            for (DexBackedStringReference reference : dex.getStringReferences()) {
                result.recordWholePool(reference.getString());
            }
            scanRuntimePayloads(dex, result);
        }
        return result.freeze(dexFiles.size(), strictWholeStringPool);
    }

    static Result verifyStrings(Iterable<String> strings, Set<String> expectedPlaintextHashes) {
        Set<String> expected = expectedPlaintextHashes == null
                ? Collections.emptySet() : new HashSet<>(expectedPlaintextHashes);
        MutableResult result = new MutableResult(expected);
        if (strings != null) {
            for (String value : strings) result.recordWholePool(value);
        }
        // This helper represents an already selected iterable rather than a DEX semantic scan.
        return result.freeze(0, true);
    }

    private static void scanRuntimePayloads(DexBackedDexFile dex, MutableResult result) {
        for (ClassDef classDef : dex.getClasses()) {
            String owner = toInternalClassName(classDef.getType());
            Set<String> ownerHashes = result.expectedByTargetClass.get(owner);
            if (result.targetClassNames.contains(owner)) result.targetClassesScanned.add(owner);
            scanAnnotations(classDef.getAnnotations(), ownerHashes, result);
            for (Field field : classDef.getFields()) {
                scanAnnotations(field.getAnnotations(), ownerHashes, result);
            }
            for (Field field : classDef.getStaticFields()) {
                String exactField = owner + "->" + field.getName() + ":" + field.getType();
                if (result.identityFieldProvenanceTargets.contains(exactField)) {
                    result.identityFieldProvenanceScanned.add(exactField);
                }
                Set<String> fieldHashes = result.expectedByTargetField.get(
                        owner + "->" + field.getName());
                if (fieldHashes != null) result.targetFieldsScanned.add(
                        owner + "->" + field.getName());
                scanEncodedValue(field.getInitialValue(), PayloadKind.STATIC_FIELD,
                        ownerHashes, fieldHashes, true, false, result);
            }
            for (Method method : classDef.getMethods()) {
                scanAnnotations(method.getAnnotations(), ownerHashes, result);
                for (MethodParameter parameter : method.getParameters()) {
                    scanAnnotations(parameter.getAnnotations(), ownerHashes, result);
                }
                MethodImplementation implementation = method.getImplementation();
                if (implementation == null) continue;
                String exactMethod = owner + "->" + method.getName()
                        + methodDescriptor(method);
                String nameOnlyMethod = owner + "->" + method.getName();
                Set<String> methodHashes = result.expectedByTargetMethod.get(exactMethod);
                if (methodHashes == null) {
                    methodHashes = result.expectedByTargetMethod.get(nameOnlyMethod);
                }
                if (methodHashes != null) {
                    result.targetMethodsScanned.add(result.expectedByTargetMethod
                            .containsKey(exactMethod) ? exactMethod : nameOnlyMethod);
                }
                for (Instruction instruction : implementation.getInstructions()) {
                    if (!(instruction instanceof ReferenceInstruction)) continue;
                    Reference reference = ((ReferenceInstruction) instruction).getReference();
                    if (reference instanceof StringReference) {
                        result.recordRuntime(((StringReference) reference).getString(),
                                PayloadKind.CONST_STRING, ownerHashes, methodHashes,
                                true, false);
                    } else if (reference instanceof CallSiteReference) {
                        CallSiteReference callSite = (CallSiteReference) reference;
                        if (!callSite.getMethodName().isEmpty()
                                && !CompilerCallSiteMetadata.isStructuralDexCallSiteName(
                                classDef.getType(), method, callSite)) {
                            result.recordRuntime(callSite.getMethodName(),
                                    PayloadKind.CALL_SITE, ownerHashes, null,
                                    false, false);
                        }
                        for (EncodedValue argument
                                : callSite.getExtraArguments()) {
                            scanEncodedValue(argument, PayloadKind.CALL_SITE,
                                    ownerHashes, null, false, false, result);
                        }
                    }
                }
            }
        }
    }

    private static void scanAnnotations(Iterable<? extends Annotation> annotations,
                                        Set<String> ownerHashes, MutableResult result) {
        if (annotations == null) return;
        for (Annotation annotation : annotations) {
            for (AnnotationElement element : annotation.getElements()) {
                boolean structural = isStructuralAnnotationElement(
                        annotation.getType(), element.getName());
                // The current transformer never selects annotation values as encryption sites.
                // Keep exact structural/ordinary diagnostics, but do not turn a same-value
                // annotation into proof that a method/field insertion failed.
                scanEncodedValue(element.getValue(), PayloadKind.ANNOTATION, ownerHashes,
                        null, false, structural, result);
            }
        }
    }

    private static void scanEncodedValue(EncodedValue value, PayloadKind kind,
                                         Set<String> ownerHashes, Set<String> gateHashes,
                                         boolean gateEligible,
                                         boolean structuralAnnotation, MutableResult result) {
        if (value == null) return;
        if (value instanceof StringEncodedValue) {
            result.recordRuntime(((StringEncodedValue) value).getValue(), kind, ownerHashes,
                    gateHashes, gateEligible, structuralAnnotation);
            return;
        }
        if (value instanceof ArrayEncodedValue) {
            for (EncodedValue nested : ((ArrayEncodedValue) value).getValue()) {
                scanEncodedValue(nested, kind, ownerHashes, gateHashes, gateEligible,
                        structuralAnnotation, result);
            }
            return;
        }
        if (value instanceof AnnotationEncodedValue) {
            AnnotationEncodedValue annotation = (AnnotationEncodedValue) value;
            for (AnnotationElement element : annotation.getElements()) {
                boolean nestedStructural = structuralAnnotation || isStructuralAnnotationElement(
                        annotation.getType(), element.getName());
                scanEncodedValue(element.getValue(), kind, ownerHashes, gateHashes,
                        gateEligible && !nestedStructural, nestedStructural, result);
            }
        }
    }

    /**
     * Only exact platform metadata elements are excluded from the runtime business-payload gate.
     * In particular, AnnotationDefault.value and Record.componentAnnotations stay gate-eligible.
     */
    private static boolean isStructuralAnnotationElement(String type, String elementName) {
        if ("value".equals(elementName)) {
            return "Ldalvik/annotation/Signature;".equals(type)
                    || "Ldalvik/annotation/SourceDebugExtension;".equals(type);
        }
        if ("name".equals(elementName)) {
            return "Ldalvik/annotation/InnerClass;".equals(type);
        }
        if ("names".equals(elementName)) {
            return "Ldalvik/annotation/MethodParameters;".equals(type);
        }
        return "componentNames".equals(elementName)
                && "Ldalvik/annotation/Record;".equals(type);
    }

    private static Map<String, Set<String>> normalizeTargetHashes(
            Map<String, ? extends Set<String>> targetHashes, Set<String> expected) {
        if (targetHashes == null) return Collections.emptyMap();
        Map<String, Set<String>> normalized = new TreeMap<>();
        for (Map.Entry<String, ? extends Set<String>> entry : targetHashes.entrySet()) {
            String owner = toInternalClassName(entry.getKey());
            if (owner.isEmpty()) {
                throw new IllegalArgumentException("target owner scope contains a blank class name");
            }
            Set<String> hashes = entry.getValue() == null
                    ? Collections.emptySet() : new TreeSet<>(entry.getValue());
            if (hashes.isEmpty()) {
                throw new IllegalArgumentException("target owner scope contains no protected hashes");
            }
            if (!expected.containsAll(hashes)) {
                throw new IllegalArgumentException(
                        "target owner scope contains an untracked protected hash");
            }
            Set<String> prior = normalized.put(owner, Collections.unmodifiableSet(hashes));
            if (prior != null) {
                throw new IllegalArgumentException("duplicate normalized target owner scope");
            }
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(normalized));
    }

    private static Map<String, Set<String>> normalizeTargetMemberHashes(
            Map<String, ? extends Set<String>> memberHashes, Set<String> expected,
            boolean method) {
        if (memberHashes == null) return Collections.emptyMap();
        Map<String, Set<String>> normalized = new TreeMap<>();
        for (Map.Entry<String, ? extends Set<String>> entry : memberHashes.entrySet()) {
            String key = normalizeTargetMemberKey(entry.getKey(), method);
            if (key.isEmpty()) {
                throw new IllegalArgumentException("target member scope contains an invalid key");
            }
            Set<String> hashes = entry.getValue() == null
                    ? Collections.emptySet() : new TreeSet<>(entry.getValue());
            if (hashes.isEmpty() || !expected.containsAll(hashes)) {
                throw new IllegalArgumentException(
                        "target member scope contains invalid protected hashes");
            }
            Set<String> previous = normalized.put(key, Collections.unmodifiableSet(hashes));
            if (previous != null) {
                throw new IllegalArgumentException("duplicate normalized target member scope");
            }
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(normalized));
    }

    private static Set<String> normalizeGlobalRuntimeFallbackHashes(
            Set<String> fallbackHashes, Set<String> expected) {
        Set<String> normalized = fallbackHashes == null
                ? Collections.emptySet() : new TreeSet<>(fallbackHashes);
        if (!expected.containsAll(normalized)) {
            throw new IllegalArgumentException(
                    "global runtime fallback contains an untracked protected hash");
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(normalized));
    }

    private static Set<String> normalizeRemovedOriginalSiteHashes(
            Set<String> removedHashes, Set<String> expected) {
        Set<String> normalized = removedHashes == null
                ? Collections.emptySet() : new TreeSet<>(removedHashes);
        if (!expected.containsAll(normalized)) {
            throw new IllegalArgumentException(
                    "removed original site scope contains an untracked protected hash");
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(normalized));
    }

    private static Set<String> normalizeIdentityFieldProvenanceTargets(Set<String> targets) {
        if (targets == null) return Collections.emptySet();
        Set<String> normalized = new TreeSet<>();
        for (String raw : targets) {
            if (raw == null) {
                throw new IllegalArgumentException("identity field provenance contains null");
            }
            String value = raw.trim();
            int arrow = value.indexOf("->");
            int colon = value.indexOf(':', arrow + 2);
            if (arrow <= 0 || colon <= arrow + 2 || colon >= value.length() - 1
                    || value.indexOf("->", arrow + 2) >= 0) {
                throw new IllegalArgumentException(
                        "identity field provenance contains an invalid exact key");
            }
            String owner = toInternalClassName(value.substring(0, arrow));
            String name = value.substring(arrow + 2, colon);
            String descriptor = value.substring(colon + 1);
            if (owner.isEmpty() || name.isEmpty() || name.indexOf('(') >= 0
                    || name.indexOf(')') >= 0 || name.indexOf('#') >= 0
                    || descriptor.indexOf(' ') >= 0 || descriptor.indexOf('\t') >= 0
                    || !(descriptor.startsWith("L") && descriptor.endsWith(";"))) {
                throw new IllegalArgumentException(
                        "identity field provenance contains an invalid exact key");
            }
            normalized.add(owner + "->" + name + ":" + descriptor);
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(normalized));
    }

    private static String normalizeTargetMemberKey(String value, boolean method) {
        if (value == null) return "";
        String trimmed = value.trim();
        int arrow = trimmed.indexOf("->");
        if (arrow <= 0 || trimmed.indexOf("->", arrow + 2) >= 0) return "";
        String owner = toInternalClassName(trimmed.substring(0, arrow));
        String member = trimmed.substring(arrow + 2);
        if (owner.isEmpty() || member.isEmpty() || member.indexOf('#') >= 0) return "";
        if (!method && (member.indexOf('(') >= 0 || member.indexOf(')') >= 0)) return "";
        if (method && member.indexOf(')') >= 0 && member.indexOf('(') <= 0) return "";
        return owner + "->" + member;
    }

    private static String toInternalClassName(String value) {
        if (value == null) return "";
        String normalized = value.trim();
        if (normalized.startsWith("L") && normalized.endsWith(";")
                && normalized.length() > 2) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        normalized = normalized.replace('.', '/');
        if (normalized.isEmpty() || normalized.startsWith("/") || normalized.endsWith("/")
                || normalized.contains("//") || normalized.indexOf(';') >= 0
                || normalized.indexOf('[') >= 0) {
            return "";
        }
        return normalized;
    }

    private static String methodDescriptor(Method method) {
        StringBuilder descriptor = new StringBuilder("(");
        for (CharSequence parameter : method.getParameterTypes()) descriptor.append(parameter);
        return descriptor.append(')').append(method.getReturnType()).toString();
    }

    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                int valueByte = b & 0xff;
                hex.append(HEX[valueByte >>> 4]).append(HEX[valueByte & 0x0f]);
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void collectDex(File file, List<File> out, Set<String> canonicalFiles)
            throws IOException {
        if (file == null || !file.exists()) return;
        if (file.isFile()) {
            if (file.getName().endsWith(".dex") && canonicalFiles.add(file.getCanonicalPath())) {
                out.add(file);
            }
            return;
        }
        File[] children = file.listFiles();
        if (children == null) {
            throw new IOException("cannot list DEX directory: " + file);
        }
        for (File child : children) collectDex(child, out, canonicalFiles);
    }

    private enum PayloadKind {
        CONST_STRING,
        STATIC_FIELD,
        ANNOTATION,
        CALL_SITE
    }

    private static final class MutableResult {
        final Set<String> expected;
        final Map<String, Set<String>> expectedByTargetClass;
        final Map<String, Set<String>> expectedByTargetMethod;
        final Map<String, Set<String>> expectedByTargetField;
        final Set<String> globalRuntimeFallbackHashes;
        final Set<String> removedOriginalSiteHashes;
        final Set<String> identityFieldProvenanceTargets;
        final Set<String> targetClassNames = new LinkedHashSet<>();
        final Set<String> scopedRuntimeMatches = new LinkedHashSet<>();
        final Set<String> globalRuntimeFallbackMatches = new LinkedHashSet<>();
        final Set<String> effectiveRuntimeMatches = new LinkedHashSet<>();
        final Set<String> ownerRuntimeMatches = new LinkedHashSet<>();
        final Set<String> globalRuntimeMatches = new LinkedHashSet<>();
        final Set<String> wholePoolMatches = new LinkedHashSet<>();
        final Set<String> targetClassesScanned = new LinkedHashSet<>();
        final Set<String> targetMethodsScanned = new LinkedHashSet<>();
        final Set<String> targetFieldsScanned = new LinkedHashSet<>();
        final Set<String> identityFieldProvenanceScanned = new LinkedHashSet<>();
        final Set<String> structuralAnnotationMatches = new LinkedHashSet<>();
        int stringPoolEntriesScanned;
        int scopedRuntimeLeakOccurrences;
        int globalRuntimeFallbackLeakOccurrences;
        int effectiveRuntimeLeakOccurrences;
        int ownerRuntimeCollisionOccurrences;
        int globalRuntimeCollisionOccurrences;
        int wholePoolCollisionOccurrences;
        int constStringReferencesScanned;
        int staticStringValuesScanned;
        int annotationStringValuesScanned;
        int callSiteStringValuesScanned;
        int structuralAnnotationStringValuesScanned;
        int structuralAnnotationCollisionOccurrences;

        MutableResult(Set<String> expected) {
            this(expected, Collections.emptyMap(), Collections.emptyMap(),
                    Collections.emptyMap(), Collections.emptySet(), Collections.emptySet(),
                    Collections.emptySet());
        }

        MutableResult(Set<String> expected, Map<String, Set<String>> expectedByTargetClass,
                      Map<String, Set<String>> expectedByTargetMethod,
                      Map<String, Set<String>> expectedByTargetField,
                      Set<String> globalRuntimeFallbackHashes,
                      Set<String> removedOriginalSiteHashes,
                      Set<String> identityFieldProvenanceTargets) {
            this.expected = expected;
            this.expectedByTargetClass = expectedByTargetClass;
            this.expectedByTargetMethod = expectedByTargetMethod;
            this.expectedByTargetField = expectedByTargetField;
            this.globalRuntimeFallbackHashes = globalRuntimeFallbackHashes;
            this.removedOriginalSiteHashes = removedOriginalSiteHashes;
            this.identityFieldProvenanceTargets = identityFieldProvenanceTargets;
            targetClassNames.addAll(expectedByTargetClass.keySet());
            for (String key : expectedByTargetMethod.keySet()) {
                targetClassNames.add(key.substring(0, key.indexOf("->")));
            }
            for (String key : expectedByTargetField.keySet()) {
                targetClassNames.add(key.substring(0, key.indexOf("->")));
            }
        }

        void recordWholePool(String value) {
            stringPoolEntriesScanned++;
            String hash = sha256(value);
            if (expected.contains(hash)) {
                wholePoolCollisionOccurrences++;
                wholePoolMatches.add(hash);
            }
        }

        void recordRuntime(String value, PayloadKind kind, Set<String> ownerHashes,
                           Set<String> gateHashes,
                           boolean gateEligible, boolean structuralAnnotation) {
            switch (kind) {
                case CONST_STRING: constStringReferencesScanned++; break;
                case STATIC_FIELD: staticStringValuesScanned++; break;
                case ANNOTATION: annotationStringValuesScanned++; break;
                case CALL_SITE: callSiteStringValuesScanned++; break;
                default: throw new IllegalStateException("unknown DEX string payload kind");
            }
            if (structuralAnnotation) structuralAnnotationStringValuesScanned++;
            String hash = sha256(value);
            if (expected.contains(hash)) {
                globalRuntimeCollisionOccurrences++;
                globalRuntimeMatches.add(hash);
                if (structuralAnnotation) {
                    structuralAnnotationCollisionOccurrences++;
                    structuralAnnotationMatches.add(hash);
                }
            }
            if (ownerHashes != null && ownerHashes.contains(hash)) {
                ownerRuntimeCollisionOccurrences++;
                ownerRuntimeMatches.add(hash);
            }
            boolean exactSiteLeak = gateEligible && gateHashes != null
                    && gateHashes.contains(hash);
            boolean fallbackLeak = !structuralAnnotation
                    && globalRuntimeFallbackHashes.contains(hash);
            if (exactSiteLeak) {
                scopedRuntimeLeakOccurrences++;
                scopedRuntimeMatches.add(hash);
            }
            if (fallbackLeak) {
                globalRuntimeFallbackLeakOccurrences++;
                globalRuntimeFallbackMatches.add(hash);
            }
            if (exactSiteLeak || fallbackLeak) {
                effectiveRuntimeLeakOccurrences++;
                effectiveRuntimeMatches.add(hash);
            }
        }

        Result freeze(int dexFilesScanned, boolean strictWholeStringPool) {
            int effectiveLeaks = strictWholeStringPool
                    ? wholePoolMatches.size() : effectiveRuntimeMatches.size();
            int effectiveOccurrences = strictWholeStringPool
                    ? wholePoolCollisionOccurrences : effectiveRuntimeLeakOccurrences;
            return new Result(dexFilesScanned, stringPoolEntriesScanned, expected.size(),
                    effectiveLeaks, effectiveOccurrences, effectiveRuntimeMatches.size(),
                    effectiveRuntimeLeakOccurrences, scopedRuntimeMatches.size(),
                    scopedRuntimeLeakOccurrences, globalRuntimeFallbackHashes.size(),
                    globalRuntimeFallbackMatches.size(),
                    globalRuntimeFallbackLeakOccurrences, ownerRuntimeMatches.size(),
                    ownerRuntimeCollisionOccurrences, globalRuntimeMatches.size(),
                    globalRuntimeCollisionOccurrences, wholePoolMatches.size(),
                    wholePoolCollisionOccurrences, targetClassNames.size(),
                    targetClassesScanned.size(), expectedByTargetMethod.size(),
                    targetMethodsScanned.size(), expectedByTargetField.size(),
                    targetFieldsScanned.size(), removedOriginalSiteHashes.size(),
                    identityFieldProvenanceTargets.size(),
                    identityFieldProvenanceScanned.size(), constStringReferencesScanned,
                    staticStringValuesScanned, annotationStringValuesScanned,
                    callSiteStringValuesScanned, structuralAnnotationStringValuesScanned,
                    structuralAnnotationMatches.size(), structuralAnnotationCollisionOccurrences,
                    strictWholeStringPool);
        }
    }

    public static final class Result {
        public final int dexFilesScanned;
        public final int stringPoolEntriesScanned;
        public final int plaintextHashesTracked;
        /** Effective gate result: runtime payloads by default, whole pool in strict mode. */
        public final int plaintextLeaks;
        public final int plaintextLeakOccurrences;
        public final int runtimePlaintextLeaks;
        public final int runtimePlaintextLeakOccurrences;
        public final int scopedRuntimePlaintextLeaks;
        public final int scopedRuntimePlaintextLeakOccurrences;
        /** Hashes whose R8 residual site was unknown and therefore use a global runtime gate. */
        public final int globalRuntimeFallbackHashesTracked;
        public final int globalRuntimeFallbackPlaintextLeaks;
        public final int globalRuntimeFallbackPlaintextLeakOccurrences;
        /** Same-value runtime payloads in a target final owner; diagnostic, not a hard gate. */
        public final int ownerRuntimePlaintextCollisions;
        public final int ownerRuntimePlaintextCollisionOccurrences;
        public final int globalRuntimePlaintextCollisions;
        public final int globalRuntimePlaintextCollisionOccurrences;
        public final int wholePoolPlaintextCollisions;
        public final int wholePoolPlaintextCollisionOccurrences;
        public final int targetClassesResolved;
        public final int targetClassesScanned;
        public final int targetMethodsResolved;
        public final int targetMethodsScanned;
        public final int targetFieldsResolved;
        public final int targetFieldsScanned;
        /** Hashes whose original executable site was affirmatively removed by R8. */
        public final int removedOriginalSiteHashesTracked;
        /** Seed-backed identity fields are presence-only provenance, never plaintext gate sites. */
        public final int identityFieldProvenanceResolved;
        public final int identityFieldProvenanceScanned;
        public final int constStringReferencesScanned;
        public final int staticStringValuesScanned;
        public final int annotationStringValuesScanned;
        public final int callSiteStringValuesScanned;
        public final int structuralAnnotationStringValuesScanned;
        public final int structuralAnnotationPlaintextCollisions;
        public final int structuralAnnotationPlaintextCollisionOccurrences;
        public final boolean strictWholeStringPool;

        Result(int dexFilesScanned, int stringPoolEntriesScanned, int plaintextHashesTracked,
               int plaintextLeaks, int plaintextLeakOccurrences,
               int runtimePlaintextLeaks, int runtimePlaintextLeakOccurrences,
               int scopedRuntimePlaintextLeaks, int scopedRuntimePlaintextLeakOccurrences,
               int globalRuntimeFallbackHashesTracked,
               int globalRuntimeFallbackPlaintextLeaks,
               int globalRuntimeFallbackPlaintextLeakOccurrences,
               int ownerRuntimePlaintextCollisions,
               int ownerRuntimePlaintextCollisionOccurrences,
               int globalRuntimePlaintextCollisions,
               int globalRuntimePlaintextCollisionOccurrences,
               int wholePoolPlaintextCollisions,
               int wholePoolPlaintextCollisionOccurrences,
               int targetClassesResolved, int targetClassesScanned,
               int targetMethodsResolved, int targetMethodsScanned,
               int targetFieldsResolved, int targetFieldsScanned,
               int removedOriginalSiteHashesTracked,
               int identityFieldProvenanceResolved,
               int identityFieldProvenanceScanned,
               int constStringReferencesScanned, int staticStringValuesScanned,
               int annotationStringValuesScanned, int callSiteStringValuesScanned,
               int structuralAnnotationStringValuesScanned,
               int structuralAnnotationPlaintextCollisions,
               int structuralAnnotationPlaintextCollisionOccurrences,
               boolean strictWholeStringPool) {
            this.dexFilesScanned = dexFilesScanned;
            this.stringPoolEntriesScanned = stringPoolEntriesScanned;
            this.plaintextHashesTracked = plaintextHashesTracked;
            this.plaintextLeaks = plaintextLeaks;
            this.plaintextLeakOccurrences = plaintextLeakOccurrences;
            this.runtimePlaintextLeaks = runtimePlaintextLeaks;
            this.runtimePlaintextLeakOccurrences = runtimePlaintextLeakOccurrences;
            this.scopedRuntimePlaintextLeaks = scopedRuntimePlaintextLeaks;
            this.scopedRuntimePlaintextLeakOccurrences = scopedRuntimePlaintextLeakOccurrences;
            this.globalRuntimeFallbackHashesTracked = globalRuntimeFallbackHashesTracked;
            this.globalRuntimeFallbackPlaintextLeaks = globalRuntimeFallbackPlaintextLeaks;
            this.globalRuntimeFallbackPlaintextLeakOccurrences =
                    globalRuntimeFallbackPlaintextLeakOccurrences;
            this.ownerRuntimePlaintextCollisions = ownerRuntimePlaintextCollisions;
            this.ownerRuntimePlaintextCollisionOccurrences =
                    ownerRuntimePlaintextCollisionOccurrences;
            this.globalRuntimePlaintextCollisions = globalRuntimePlaintextCollisions;
            this.globalRuntimePlaintextCollisionOccurrences =
                    globalRuntimePlaintextCollisionOccurrences;
            this.wholePoolPlaintextCollisions = wholePoolPlaintextCollisions;
            this.wholePoolPlaintextCollisionOccurrences = wholePoolPlaintextCollisionOccurrences;
            this.targetClassesResolved = targetClassesResolved;
            this.targetClassesScanned = targetClassesScanned;
            this.targetMethodsResolved = targetMethodsResolved;
            this.targetMethodsScanned = targetMethodsScanned;
            this.targetFieldsResolved = targetFieldsResolved;
            this.targetFieldsScanned = targetFieldsScanned;
            this.removedOriginalSiteHashesTracked = removedOriginalSiteHashesTracked;
            this.identityFieldProvenanceResolved = identityFieldProvenanceResolved;
            this.identityFieldProvenanceScanned = identityFieldProvenanceScanned;
            this.constStringReferencesScanned = constStringReferencesScanned;
            this.staticStringValuesScanned = staticStringValuesScanned;
            this.annotationStringValuesScanned = annotationStringValuesScanned;
            this.callSiteStringValuesScanned = callSiteStringValuesScanned;
            this.structuralAnnotationStringValuesScanned =
                    structuralAnnotationStringValuesScanned;
            this.structuralAnnotationPlaintextCollisions =
                    structuralAnnotationPlaintextCollisions;
            this.structuralAnnotationPlaintextCollisionOccurrences =
                    structuralAnnotationPlaintextCollisionOccurrences;
            this.strictWholeStringPool = strictWholeStringPool;
        }
    }
}
