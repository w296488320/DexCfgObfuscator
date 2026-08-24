package com.hunter.dexcfgobf.string;

import groovy.lang.Closure;
import org.gradle.api.logging.Logger;
import org.gradle.api.logging.Logging;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** 一个 Android variant 的构建期字符串处理上下文。 */
public final class StringEncryptionContext {
    private static final Logger LOGGER = Logging.getLogger(StringEncryptionContext.class);
    static final String METHOD_MARKER_SIMPLE_NAME = "ExactStringSite";
    /** Extension objects are shared by variants; serialize custom invocations across contexts. */
    private static final Object INVOCATION_LOCK = new Object();
    private final CipherInvoker cipher;
    /** Only present when build-time encryption and Android runtime decryption use different objects. */
    private final RuntimeDecryptInvoker runtimeDecryptVerifier;
    private final KeyInvoker keyGenerator;
    private final List<String> includePrefixes;
    private final List<String> excludePrefixes;
    private final String bridgeClassName;
    private final String bridgeInternalName;
    private final String methodMarkerAnnotationClassName;
    private final String methodMarkerAnnotationDescriptor;
    private final String implementationClassName;
    private final StringEncryptionMode mode;
    private final int maxStringBytes;
    private final boolean debug;
    private final boolean verifyRoundTrip;
    private final boolean allowIdentityCiphertext;
    private final boolean failOnUnsupportedStringConstants;
    private final String configurationFingerprint;
    private final String bridgeByteDecryptorOriginalMethodKey;
    private final String bridgeStringDecryptorOriginalMethodKey;
    private final String runtimeDecryptorOriginalMethodKey;

    private final AtomicInteger classesVisited = new AtomicInteger();
    private final AtomicInteger constantsEncrypted = new AtomicInteger();
    private final AtomicInteger constantsSkipped = new AtomicInteger();
    private final AtomicInteger skippedWhitespace = new AtomicInteger();
    private final AtomicInteger skippedTooLarge = new AtomicInteger();
    private final AtomicInteger skippedInvalidUnicode = new AtomicInteger();
    private final AtomicInteger skippedFiltered = new AtomicInteger();
    private final AtomicInteger unsupportedConstants = new AtomicInteger();
    private final AtomicInteger identityCiphertexts = new AtomicInteger();
    private final AtomicBoolean byteCarrierUsed = new AtomicBoolean();
    private final AtomicBoolean stringCarrierUsed = new AtomicBoolean();
    private final Set<String> visitedClasses = ConcurrentHashMap.newKeySet();
    private final Set<String> modifiedClasses = ConcurrentHashMap.newKeySet();
    private final Set<String> encryptedPlaintextHashes = ConcurrentHashMap.newKeySet();
    private final Map<String, Set<String>> encryptedPlaintextHashesByOriginalClass =
            new ConcurrentHashMap<>();
    private final Map<String, Set<String>> encryptedPlaintextHashesByOriginalMethod =
            new ConcurrentHashMap<>();
    private final Map<String, Set<String>> encryptedPlaintextHashesByOriginalField =
            new ConcurrentHashMap<>();

    public static StringEncryptionContext create(Object algorithm,
                                                 String implementationClassName,
                                                 Object keyGenerator,
                                                 Collection<String> includePrefixes,
                                                 Collection<String> excludePrefixes,
                                                 String bridgeClassName,
                                                 Object mode,
                                                 long seed,
                                                 int maxStringBytes,
                                                 boolean debug,
                                                 boolean verifyRoundTrip,
                                                 boolean allowIdentityCiphertext,
                                                 boolean decryptorStatic) {
        return create(algorithm, implementationClassName, keyGenerator, includePrefixes,
                excludePrefixes, bridgeClassName, mode, seed, maxStringBytes, debug,
                verifyRoundTrip, allowIdentityCiphertext, decryptorStatic, true);
    }

    public static StringEncryptionContext create(Object algorithm,
                                                 String implementationClassName,
                                                 Object keyGenerator,
                                                 Collection<String> includePrefixes,
                                                 Collection<String> excludePrefixes,
                                                 String bridgeClassName,
                                                 Object mode,
                                                 long seed,
                                                 int maxStringBytes,
                                                 boolean debug,
                                                 boolean verifyRoundTrip,
                                                 boolean allowIdentityCiphertext,
                                                 boolean decryptorStatic,
                                                 boolean failOnUnsupportedStringConstants) {
        if (maxStringBytes < 1) {
            throw new IllegalArgumentException("stringEncryption.maxStringBytes must be positive");
        }
        String implementation = trimToNull(implementationClassName);
        if (algorithm != null && implementation == null
                && !(algorithm instanceof StreamXorStringCipher)) {
            throw new IllegalArgumentException("custom stringEncryption.algorithm requires "
                    + "implementation = 'runtime.decryptor.Class' so the generated Android bridge "
                    + "uses the matching decrypt algorithm");
        }
        RuntimeImplementation runtimeImplementation = implementation == null ? null
                : validateRuntimeImplementation(implementation, decryptorStatic);
        Object cipherObject = algorithm;
        if (cipherObject == null && implementation != null) {
            if (decryptorStatic) {
                cipherObject = runtimeImplementation.type;
            } else {
                cipherObject = runtimeImplementation.instance;
            }
        }
        if (cipherObject == null) {
            cipherObject = new StreamXorStringCipher();
        }
        Object kg = keyGenerator == null ? new ContextHashKeyGenerator(seed) : keyGenerator;
        RuntimeImplementation runtimeVerifierImplementation = runtimeImplementation;
        if (runtimeImplementation != null && runtimeImplementation.instance != null) {
            // The generated Android bridge creates its own implementation instance. Verify with a
            // second construction even when a separate build-time algorithm is configured, so
            // per-instance constructor state cannot pass against the first build-time instance and
            // then fail when Android constructs the runtime implementation.
            runtimeVerifierImplementation = runtimeImplementation.newIndependentInstance();
        }
        RuntimeDecryptInvoker runtimeDecryptVerifier = runtimeVerifierImplementation == null
                ? null : new RuntimeDecryptInvoker(runtimeVerifierImplementation);
        return new StringEncryptionContext(
                new CipherInvoker(cipherObject),
                runtimeDecryptVerifier,
                new KeyInvoker(kg),
                normalizePrefixes(includePrefixes),
                normalizePrefixes(excludePrefixes),
                requireClassName(bridgeClassName, "generated bridge class"),
                implementation,
                StringEncryptionMode.from(mode),
                maxStringBytes,
                debug,
                verifyRoundTrip,
                allowIdentityCiphertext,
                failOnUnsupportedStringConstants,
                runtimeDecryptorOriginalMethodKey(runtimeImplementation));
    }

    private StringEncryptionContext(CipherInvoker cipher,
                                    RuntimeDecryptInvoker runtimeDecryptVerifier,
                                    KeyInvoker keyGenerator,
                                    List<String> includePrefixes,
                                    List<String> excludePrefixes,
                                    String bridgeClassName,
                                    String implementationClassName,
                                    StringEncryptionMode mode,
                                    int maxStringBytes,
                                    boolean debug,
                                    boolean verifyRoundTrip,
                                    boolean allowIdentityCiphertext,
                                    boolean failOnUnsupportedStringConstants,
                                    String runtimeDecryptorOriginalMethodKey) {
        if (includePrefixes.isEmpty()) {
            throw new IllegalArgumentException("stringEncryption requires packages/fogPackages "
                    + "or an inherited dexControlFlowObfuscator.dexObfuscator.obfClass");
        }
        this.cipher = cipher;
        this.runtimeDecryptVerifier = runtimeDecryptVerifier;
        this.keyGenerator = keyGenerator;
        this.includePrefixes = includePrefixes;
        this.excludePrefixes = excludePrefixes;
        this.bridgeClassName = bridgeClassName;
        this.bridgeInternalName = bridgeClassName.replace('.', '/');
        this.methodMarkerAnnotationClassName = bridgeClassName + "$"
                + METHOD_MARKER_SIMPLE_NAME;
        this.methodMarkerAnnotationDescriptor = "L" + bridgeInternalName + "$"
                + METHOD_MARKER_SIMPLE_NAME + ";";
        this.implementationClassName = implementationClassName;
        this.mode = mode;
        this.maxStringBytes = maxStringBytes;
        this.debug = debug;
        this.verifyRoundTrip = verifyRoundTrip;
        this.allowIdentityCiphertext = allowIdentityCiphertext;
        this.failOnUnsupportedStringConstants = failOnUnsupportedStringConstants;
        this.bridgeByteDecryptorOriginalMethodKey = bridgeInternalName
                + "->decrypt([B[B)Ljava/lang/String;";
        this.bridgeStringDecryptorOriginalMethodKey = bridgeInternalName
                + "->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
        this.runtimeDecryptorOriginalMethodKey = runtimeDecryptorOriginalMethodKey;
        this.configurationFingerprint = fingerprint(cipher.target) + ":"
                + fingerprint(keyGenerator.target)
                + (runtimeDecryptVerifier == null ? ""
                : ":" + fingerprint(runtimeDecryptVerifier.runtime.type));
    }

    public boolean shouldVisitClass(String className) {
        String normalized = normalizeClassName(className);
        if (normalized.isEmpty() || isGeneratedOrRuntimeClass(normalized) || isAndroidGeneratedClass(normalized)) {
            return false;
        }
        for (String prefix : excludePrefixes) {
            if (matchesPrefix(normalized, prefix)) return false;
        }
        for (String prefix : includePrefixes) {
            if (matchesPrefix(normalized, prefix)) return true;
        }
        return false;
    }

    void recordClassVisit(String className) {
        if (visitedClasses.add(normalizeClassName(className))) classesVisited.incrementAndGet();
    }

    EncryptedString encrypt(String value, String owner, String location) {
        if (value == null) return null;
        byte[] plain = value.getBytes(StandardCharsets.UTF_8);
        if (plain.length == 0 || value.trim().isEmpty()) {
            constantsSkipped.incrementAndGet();
            skippedWhitespace.incrementAndGet();
            return null;
        }
        if (plain.length > maxStringBytes) {
            constantsSkipped.incrementAndGet();
            skippedTooLarge.incrementAndGet();
            return null;
        }
        if (hasUnpairedSurrogate(value)) {
            constantsSkipped.incrementAndGet();
            skippedInvalidUnicode.incrementAndGet();
            return null;
        }
        byte[] key;
        byte[] encrypted;
        String buildRoundTrip = null;
        String runtimeRoundTrip = null;
        boolean accepted;
        synchronized (INVOCATION_LOCK) {
            accepted = cipher.shouldEncrypt(value);
            if (!accepted) {
                constantsSkipped.incrementAndGet();
                skippedFiltered.incrementAndGet();
                return null;
            }
            key = keyGenerator.generate(value, location);
            if (key == null) {
                throw new IllegalArgumentException("string key generator returned null at " + location);
            }
            encrypted = cipher.encrypt(value, key);
            if (encrypted != null && verifyRoundTrip) {
                buildRoundTrip = cipher.decrypt(encrypted.clone(), key.clone());
            }
            if (encrypted != null && runtimeDecryptVerifier != null) {
                runtimeRoundTrip = runtimeDecryptVerifier.decrypt(
                        encrypted.clone(), key.clone(), location);
            }
        }
        if (encrypted == null) {
            throw new IllegalArgumentException("string cipher returned null at " + location);
        }
        if (Arrays.equals(plain, key)) {
            throw new IllegalArgumentException("string key generator returned plaintext bytes at "
                    + location + "; key material must not directly carry the protected value");
        }
        if ((long) encrypted.length + key.length > maxStringBytes * 2L) {
            throw new IllegalArgumentException("encrypted string/key exceeds safe bytecode budget at "
                    + location + ": " + encrypted.length + "+" + key.length);
        }
        boolean identity = Arrays.equals(plain, encrypted);
        if (identity) {
            identityCiphertexts.incrementAndGet();
            if (!allowIdentityCiphertext) {
                throw new IllegalArgumentException("string cipher returned plaintext bytes at "
                        + location + "; use a real reversible transform or explicitly set "
                        + "allowIdentityCiphertext true");
            }
        }
        // A custom transform can be non-identity yet still emit `prefix + plaintext + suffix`, or
        // use the raw plaintext as part of its key. Both carriers are recoverable directly from
        // BYTES arrays or after Base64 decoding and would bypass the final String-pool gate. Limit
        // the substring check to sufficiently long values so random binary material cannot create
        // meaningful false positives; exact plaintext-as-key is rejected above for every length.
        if (plain.length >= 8 && (containsBytes(encrypted, plain) || containsBytes(key, plain))) {
            throw new IllegalArgumentException("string cipher/key material contains the complete "
                    + "plaintext byte sequence at " + location
                    + "; custom carriers must not embed protected values verbatim");
        }
        if (verifyRoundTrip && !value.equals(buildRoundTrip)) {
            throw new IllegalArgumentException("custom string cipher round-trip failed at " + location
                    + "; build-time decrypt(encrypt(value,key),key) must equal the original string");
        }
        if (runtimeDecryptVerifier != null && !value.equals(runtimeRoundTrip)) {
            throw new IllegalArgumentException("runtime string implementation round-trip failed at "
                    + location + "; implementation.decrypt(buildEncrypt(value,key),key) must equal "
                    + "the original string");
        }
        String normalizedOwner = normalizeClassName(owner);
        if (normalizedOwner.isEmpty()) {
            throw new IllegalArgumentException("encrypted string owner is missing at " + location);
        }
        String plaintextHash = StringPlaintextVerifier.sha256(value);
        constantsEncrypted.incrementAndGet();
        modifiedClasses.add(normalizedOwner);
        encryptedPlaintextHashes.add(plaintextHash);
        encryptedPlaintextHashesByOriginalClass
                .computeIfAbsent(normalizedOwner, ignored -> ConcurrentHashMap.newKeySet())
                .add(plaintextHash);
        String member = memberScopeFromLocation(owner, location);
        if (location.endsWith(":field")) {
            // A static-final ConstantValue is cleared and the decrypt call is emitted into the
            // class initializer. Keep the field relation only as provenance; the executable DEX
            // gate site is owner-><clinit>()V, not the field's encoded initial value.
            encryptedPlaintextHashesByOriginalField
                    .computeIfAbsent(member, ignored -> ConcurrentHashMap.newKeySet())
                    .add(plaintextHash);
            String classInitializer = normalizedOwner.replace('.', '/') + "-><clinit>()V";
            encryptedPlaintextHashesByOriginalMethod
                    .computeIfAbsent(classInitializer,
                            ignored -> ConcurrentHashMap.newKeySet())
                    .add(plaintextHash);
        } else {
            encryptedPlaintextHashesByOriginalMethod
                    .computeIfAbsent(member, ignored -> ConcurrentHashMap.newKeySet())
                    .add(plaintextHash);
        }
        if (debug) {
            LOGGER.lifecycle("[dex-cfg-obf] string encrypted at {} (plainBytes={}, cipherBytes={}, "
                    + "keyBytes={}, mode={})", location, plain.length, encrypted.length, key.length,
                    mode);
        }
        return new EncryptedString(encrypted.clone(), key.clone(), identity);
    }

    private static boolean containsBytes(byte[] carrier, byte[] value) {
        if (carrier == null || value == null || value.length == 0
                || carrier.length < value.length) {
            return false;
        }
        outer:
        for (int offset = 0; offset <= carrier.length - value.length; offset++) {
            for (int i = 0; i < value.length; i++) {
                if (carrier[offset + i] != value[i]) continue outer;
            }
            return true;
        }
        return false;
    }

    void recordUnsupportedStringConstant(String kind, String location) {
        int count = unsupportedConstants.incrementAndGet();
        if (debug) {
            LOGGER.lifecycle("[dex-cfg-obf] unsupported executable string constant at {} "
                    + "(kind={}, count={})", location, kind, count);
        }
        if (failOnUnsupportedStringConstants) {
            throw new IllegalStateException("unsupported executable string constant (" + kind
                    + ") at " + location + "; this bootstrap value cannot be rewritten safely. "
                    + "Rewrite it as an ordinary String expression, exclude the class/method "
                    + "intentionally, or set stringEncryption.failOnUnsupportedStringConstants "
                    + "false to retain it and report the unsupported count");
        }
    }

    public StringEncryptionSnapshot snapshot() {
        return new StringEncryptionSnapshot(true, mode.name(), classesVisited.get(),
                modifiedClasses.size(), constantsEncrypted.get(), constantsSkipped.get(),
                skippedWhitespace.get(), skippedTooLarge.get(), skippedInvalidUnicode.get(),
                skippedFiltered.get(), unsupportedConstants.get(), identityCiphertexts.get(),
                encryptedPlaintextHashes, visitedClasses,
                encryptedPlaintextHashesByOriginalClass,
                encryptedPlaintextHashesByOriginalMethod,
                encryptedPlaintextHashesByOriginalField);
    }

    /** Library constant-pool rebuilding must touch only classes whose bytecode was modified. */
    boolean wasClassModified(String className) {
        return modifiedClasses.contains(normalizeClassName(className));
    }

    public String getConfigurationFingerprint() {
        return configurationFingerprint;
    }

    public Set<String> getRequiredDecryptorOriginalMethodKeys() {
        return requiredDecryptorOriginalMethodKeys(
                byteCarrierUsed.get(), stringCarrierUsed.get());
    }

    /**
     * Recovers the exact carrier usage from transformed class artifacts. Unlike the in-memory
     * counters, this remains authoritative when Gradle restores the ASM task from an up-to-date or
     * build-cache result and no visitor runs in the current process.
     */
    public Set<String> discoverRequiredDecryptorOriginalMethodKeys(Collection<File> outputs)
            throws java.io.IOException {
        StringClassConstantPoolCompactor.BridgeUsage usage =
                StringClassConstantPoolCompactor.scanBridgeUsage(outputs, bridgeInternalName);
        return requiredDecryptorOriginalMethodKeys(
                usage.byteCarrierCalled, usage.stringCarrierCalled);
    }

    void recordByteCarrierUsage() {
        byteCarrierUsed.set(true);
    }

    void recordBase64CarrierUsage() {
        // The generated String overload decodes its arguments and delegates to the byte[] overload.
        stringCarrierUsed.set(true);
        byteCarrierUsed.set(true);
    }

    private Set<String> requiredDecryptorOriginalMethodKeys(boolean byteUsed,
                                                             boolean stringUsed) {
        TreeSet<String> keys = new TreeSet<>();
        if (byteUsed || stringUsed) {
            keys.add(bridgeByteDecryptorOriginalMethodKey);
            if (stringUsed) keys.add(bridgeStringDecryptorOriginalMethodKey);
            if (runtimeDecryptorOriginalMethodKey != null) {
                keys.add(runtimeDecryptorOriginalMethodKey);
            }
        }
        return Collections.unmodifiableSet(keys);
    }

    private static String runtimeDecryptorOriginalMethodKey(
            RuntimeImplementation runtimeImplementation) {
        if (runtimeImplementation == null) return null;
        String declaringOwner = runtimeImplementation.decrypt.getDeclaringClass().getName()
                .replace('.', '/');
        return declaringOwner + "->decrypt([B[B)Ljava/lang/String;";
    }

    private static String fingerprint(Object target) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            Class<?> type = target instanceof Class<?> ? (Class<?>) target : target.getClass();
            digest.update(type.getName().getBytes(StandardCharsets.UTF_8));
            String resource = "/" + type.getName().replace('.', '/') + ".class";
            try (InputStream input = type.getResourceAsStream(resource)) {
                if (input != null) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
                }
            }
            if (!(target instanceof Class<?>)) {
                // Always bind object identity/state. Object.toString intentionally busts caches for
                // custom mutable components that do not define a deterministic fingerprint; stable
                // cache reuse requires an explicit deterministic toString implementation.
                digest.update(target.toString().getBytes(StandardCharsets.UTF_8));
            }
            StringBuilder hex = new StringBuilder(64);
            for (byte b : digest.digest()) hex.append(String.format("%02x", b & 0xff));
            return hex.toString();
        } catch (Exception failure) {
            throw new IllegalArgumentException("cannot fingerprint custom string component "
                    + (target instanceof Class<?> ? ((Class<?>) target).getName()
                    : target.getClass().getName()), failure);
        }
    }

    String getBridgeInternalName() {
        return bridgeInternalName;
    }

    /** Per-module CLASS-retention marker consumed by the final R8 invocation. */
    String getMethodMarkerAnnotationDescriptor() {
        return methodMarkerAnnotationDescriptor;
    }

    public String getMethodMarkerAnnotationClassName() {
        return methodMarkerAnnotationClassName;
    }

    StringEncryptionMode getMode() {
        return mode;
    }

    boolean isDebug() {
        return debug;
    }

    private boolean isGeneratedOrRuntimeClass(String normalized) {
        if (normalized.equals(bridgeClassName) || normalized.startsWith(bridgeClassName + "$")) return true;
        return implementationClassName != null && (normalized.equals(implementationClassName)
                || normalized.startsWith(implementationClassName + "$"));
    }

    private static boolean isAndroidGeneratedClass(String normalized) {
        int dot = normalized.lastIndexOf('.');
        String simple = dot < 0 ? normalized : normalized.substring(dot + 1);
        return "BuildConfig".equals(simple) || "R".equals(simple) || simple.startsWith("R$")
                || "R2".equals(simple) || simple.startsWith("R2$");
    }

    private static boolean matchesPrefix(String className, String prefix) {
        return className.equals(prefix) || className.startsWith(prefix + ".")
                || className.startsWith(prefix + "$");
    }

    private static boolean hasUnpairedSurrogate(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    return true;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> normalizePrefixes(Collection<String> prefixes) {
        if (prefixes == null) return Collections.emptyList();
        List<String> result = new ArrayList<>();
        for (String prefix : prefixes) {
            String normalized = normalizeClassName(prefix);
            while (normalized.endsWith(".")) {
                normalized = normalized.substring(0, normalized.length() - 1);
            }
            if (!normalized.isEmpty() && !result.contains(normalized)) result.add(normalized);
        }
        return Collections.unmodifiableList(result);
    }

    private static String normalizeClassName(String className) {
        if (className == null) return "";
        String normalized = className.trim().replace('/', '.');
        if (normalized.startsWith("L") && normalized.endsWith(";") && normalized.length() > 2) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return normalized;
    }

    private static String memberScopeFromLocation(String owner, String location) {
        String internalOwner = normalizeClassName(owner).replace('.', '/');
        String prefix = owner + "->";
        if (location == null || !location.startsWith(prefix)) {
            throw new IllegalArgumentException("encrypted string member scope is missing");
        }
        String member = location.substring(prefix.length());
        if (member.endsWith(":field")) {
            member = member.substring(0, member.length() - ":field".length());
        } else {
            int ordinal = member.lastIndexOf('#');
            if (ordinal <= 0) {
                throw new IllegalArgumentException("encrypted string method scope is missing");
            }
            member = member.substring(0, ordinal);
        }
        if (member.isEmpty()) {
            throw new IllegalArgumentException("encrypted string member scope is empty");
        }
        return internalOwner + "->" + member;
    }

    private static String requireClassName(String value, String label) {
        String name = trimToNull(value);
        if (name == null || !name.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")) {
            throw new IllegalArgumentException("invalid " + label + ": " + value);
        }
        return name;
    }

    private static String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * The build-time cipher may be supplied as a separate object, but generated Android code always
     * invokes {@code implementation}. Validate that runtime-facing contract independently so a bad
     * static/instance choice fails during plugin configuration instead of generated-source compile.
     */
    private static RuntimeImplementation validateRuntimeImplementation(String className,
                                                                       boolean decryptorStatic) {
        Class<?> type = loadClass(className);
        if (!Modifier.isPublic(type.getModifiers())) {
            throw new IllegalArgumentException("stringEncryption implementation class must be public: "
                    + className);
        }

        Method decrypt;
        try {
            // getMethod intentionally accepts public inherited/interface methods and rejects a
            // private/package-private method that generated source could not call.
            decrypt = type.getMethod("decrypt", byte[].class, byte[].class);
        } catch (NoSuchMethodException failure) {
            throw new IllegalArgumentException("stringEncryption implementation " + className
                    + " must define public String decrypt(byte[], byte[])", failure);
        }
        if (decrypt.getReturnType() != String.class) {
            throw new IllegalArgumentException("runtime decrypt must return java.lang.String: "
                    + className);
        }
        rejectCheckedExceptions(decrypt.getExceptionTypes(),
                "runtime decrypt", className);
        boolean methodStatic = Modifier.isStatic(decrypt.getModifiers());
        if (decryptorStatic != methodStatic) {
            throw new IllegalArgumentException("runtime decrypt must be public "
                    + (decryptorStatic ? "static" : "non-static")
                    + " when stringEncryption.decryptorStatic is " + decryptorStatic + ": "
                    + className);
        }

        Object instance = null;
        java.lang.reflect.Constructor<?> constructor = null;
        if (!decryptorStatic) {
            if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
                throw new IllegalArgumentException("instance stringEncryption implementation must be "
                        + "a concrete public class: " + className);
            }
            try {
                constructor = type.getConstructor();
            } catch (NoSuchMethodException failure) {
                throw new IllegalArgumentException("instance stringEncryption implementation requires a "
                        + "public no-arg constructor: " + className, failure);
            }
            rejectCheckedExceptions(constructor.getExceptionTypes(),
                    "runtime implementation public no-arg constructor", className);
            instance = instantiate(type, constructor, className);
        }
        return new RuntimeImplementation(type, decrypt, instance, constructor);
    }

    private static Object instantiate(Class<?> type,
                                      java.lang.reflect.Constructor<?> constructor,
                                      String className) {
        try {
            return constructor.newInstance();
        } catch (Throwable failure) {
            throw new IllegalArgumentException("stringEncryption implementation class not constructible: "
                    + className, failure);
        }
    }

    private static void rejectCheckedExceptions(Class<?>[] exceptionTypes,
                                                String member,
                                                String className) {
        for (Class<?> exceptionType : exceptionTypes) {
            if (!RuntimeException.class.isAssignableFrom(exceptionType)
                    && !Error.class.isAssignableFrom(exceptionType)) {
                throw new IllegalArgumentException(member + " must not declare checked exception "
                        + exceptionType.getName() + ": " + className);
            }
        }
    }

    private static Class<?> loadClass(String className) {
        List<ClassLoader> loaders = new ArrayList<>();
        loaders.add(Thread.currentThread().getContextClassLoader());
        loaders.add(StringEncryptionContext.class.getClassLoader());
        Throwable last = null;
        for (ClassLoader loader : loaders) {
            if (loader == null) continue;
            try {
                return Class.forName(className, true, loader);
            } catch (Throwable failure) {
                last = failure;
            }
        }
        throw new IllegalArgumentException("stringEncryption implementation class not found: "
                + className + "; place the build-time copy in buildSrc or set algorithm = new ...()", last);
    }

    private static Method method(Class<?> type, String name, Class<?>... parameterTypes) {
        Class<?> cursor = type;
        while (cursor != null) {
            try {
                Method method = cursor.getDeclaredMethod(name, parameterTypes);
                method.setAccessible(true);
                return method;
            } catch (NoSuchMethodException ignored) {
                cursor = cursor.getSuperclass();
            }
        }
        return null;
    }

    private static RuntimeException invocationFailure(String operation, Throwable failure) {
        Throwable cause = failure instanceof InvocationTargetException
                && ((InvocationTargetException) failure).getTargetException() != null
                ? ((InvocationTargetException) failure).getTargetException() : failure;
        return cause instanceof RuntimeException ? (RuntimeException) cause
                : new IllegalArgumentException("custom string " + operation + " failed", cause);
    }

    private static final class RuntimeImplementation {
        final Class<?> type;
        final Method decrypt;
        final Object instance;
        final java.lang.reflect.Constructor<?> constructor;

        RuntimeImplementation(Class<?> type, Method decrypt, Object instance,
                              java.lang.reflect.Constructor<?> constructor) {
            this.type = type;
            this.decrypt = decrypt;
            this.instance = instance;
            this.constructor = constructor;
        }

        RuntimeImplementation newIndependentInstance() {
            if (constructor == null) return this;
            return new RuntimeImplementation(type, decrypt,
                    instantiate(type, constructor, type.getName()), constructor);
        }
    }

    /** Invokes the same public contract that the generated Android bridge will call. */
    private static final class RuntimeDecryptInvoker {
        final RuntimeImplementation runtime;

        RuntimeDecryptInvoker(RuntimeImplementation runtime) {
            this.runtime = runtime;
        }

        String decrypt(byte[] value, byte[] key, String location) {
            try {
                return (String) runtime.decrypt.invoke(runtime.instance, value, key);
            } catch (Throwable failure) {
                Throwable cause = failure instanceof InvocationTargetException
                        && ((InvocationTargetException) failure).getTargetException() != null
                        ? ((InvocationTargetException) failure).getTargetException() : failure;
                throw new IllegalArgumentException("runtime string implementation decrypt failed at "
                        + location + "; the build-time implementation copy must be callable", cause);
            }
        }
    }

    private static final class CipherInvoker {
        private final Object target;
        private final Object invocationTarget;
        private final Method encrypt;
        private final Method decrypt;
        private final Method should;

        CipherInvoker(Object target) {
            this.target = target;
            this.invocationTarget = target instanceof Class<?> ? null : target;
            Class<?> type = target instanceof Class<?> ? (Class<?>) target : target.getClass();
            this.encrypt = target instanceof StringCipher ? null
                    : method(type, "encrypt", String.class, byte[].class);
            this.decrypt = target instanceof StringCipher ? null
                    : method(type, "decrypt", byte[].class, byte[].class);
            Method preferred = method(type, "shouldEncrypt", String.class);
            this.should = preferred != null ? preferred
                    : method(type, "shouldFog", String.class);
            if (!(target instanceof StringCipher) && (encrypt == null || decrypt == null)) {
                throw new IllegalArgumentException("custom string algorithm " + type.getName()
                        + " must define byte[] encrypt(String, byte[]) and String decrypt(byte[], byte[])");
            }
            if (!(target instanceof StringCipher)) {
                validateMethod(encrypt, byte[].class, target instanceof Class<?>, "encrypt");
                validateMethod(decrypt, String.class, target instanceof Class<?>, "decrypt");
                if (should != null) validateMethod(should, boolean.class,
                        target instanceof Class<?>, "shouldEncrypt/shouldFog");
            }
        }

        boolean shouldEncrypt(String value) {
            if (target instanceof StringCipher) return ((StringCipher) target).shouldEncrypt(value);
            if (should == null) return true;
            try {
                Object result = should.invoke(invocationTarget, value);
                if (!(result instanceof Boolean)) {
                    throw new IllegalArgumentException("shouldEncrypt/shouldFog must return boolean");
                }
                return (Boolean) result;
            } catch (Throwable failure) {
                throw invocationFailure("filter", failure);
            }
        }

        byte[] encrypt(String value, byte[] key) {
            if (target instanceof StringCipher) return ((StringCipher) target).encrypt(value, key);
            try {
                Object result = encrypt.invoke(invocationTarget, value, key);
                if (!(result instanceof byte[])) {
                    throw new IllegalArgumentException("encrypt must return byte[]");
                }
                return (byte[]) result;
            } catch (Throwable failure) {
                throw invocationFailure("encrypt", failure);
            }
        }

        String decrypt(byte[] value, byte[] key) {
            if (target instanceof StringCipher) return ((StringCipher) target).decrypt(value, key);
            try {
                Object result = decrypt.invoke(invocationTarget, value, key);
                if (!(result instanceof String)) {
                    throw new IllegalArgumentException("decrypt must return String");
                }
                return (String) result;
            } catch (Throwable failure) {
                throw invocationFailure("decrypt verification", failure);
            }
        }

        private static void validateMethod(Method method, Class<?> returnType,
                                           boolean requireStatic, String name) {
            if (method.getReturnType() != returnType) {
                throw new IllegalArgumentException(name + " must return " + returnType.getTypeName());
            }
            if (!Modifier.isPublic(method.getModifiers())) {
                throw new IllegalArgumentException(name + " must be public");
            }
            if (requireStatic && !Modifier.isStatic(method.getModifiers())) {
                throw new IllegalArgumentException(name + " must be static when decryptorStatic is true");
            }
        }
    }

    private static final class KeyInvoker {
        private final Object target;
        private final Method contextual;
        private final Method legacy;

        KeyInvoker(Object target) {
            this.target = target;
            this.contextual = target instanceof StringKeyGenerator ? null
                    : method(target.getClass(), "generate", String.class, String.class);
            this.legacy = target instanceof StringKeyGenerator || contextual != null ? null
                    : method(target.getClass(), "generate", String.class);
            if (!(target instanceof StringKeyGenerator) && contextual == null && legacy == null
                    && !(target instanceof Closure)) {
                throw new IllegalArgumentException("custom keyGenerator " + target.getClass().getName()
                        + " must define byte[] generate(String[, String])");
            }
        }

        byte[] generate(String value, String location) {
            try {
                Object result;
                if (target instanceof StringKeyGenerator) {
                    result = ((StringKeyGenerator) target).generate(value, location);
                } else if (target instanceof Closure) {
                    Closure<?> closure = (Closure<?>) target;
                    result = closure.getMaximumNumberOfParameters() >= 2
                            ? closure.call(value, location) : closure.call(value);
                } else if (contextual != null) {
                    result = contextual.invoke(target, value, location);
                } else {
                    result = legacy.invoke(target, value);
                }
                if (!(result instanceof byte[])) {
                    throw new IllegalArgumentException("keyGenerator must return byte[]");
                }
                return (byte[]) result;
            } catch (Throwable failure) {
                throw invocationFailure("key generation", failure);
            }
        }
    }
}
