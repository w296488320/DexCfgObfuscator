package com.hunter.dexcfgobf.string;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GenerateStringDecryptorTaskTest {

    @Test
    public void builtInBridgeContainsMatchingStreamCipherAndInterning() {
        String source = GenerateStringDecryptorTask.renderSource(
                "fixture", "DexStringDecryptor", "", false);
        assertTrue(source.contains("state ^= state << 13"));
        assertTrue(source.contains("int mask = state & 0xff"));
        assertTrue(source.contains("if (mask == 0) mask = 0xA5"));
        assertTrue(source.contains("value[i] ^ mask"));
        assertTrue(source.contains("StandardCharsets.UTF_8).intern()"));
        assertFalse(source.contains("empty key"));
        assertFalse(source.contains("string decryptor returned null"));
        assertTrue(source.contains("Base64.decode"));
        assertFalse(source.contains(" IMPL "));
        assertTrue(source.contains("RetentionPolicy.CLASS"));
        assertTrue(source.contains("ElementType.METHOD"));
        assertTrue(source.contains("ElementType.CONSTRUCTOR"));
        assertTrue(source.contains("public @interface ExactStringSite"));
        assertFalse(source.toLowerCase(java.util.Locale.ROOT).contains("stringfog"));
    }

    @Test
    public void customBridgeSupportsInstanceAndStaticDecryptors() {
        String instance = GenerateStringDecryptorTask.renderSource(
                "fixture", "Bridge", "fixture.CustomCipher", false);
        assertTrue(instance.contains("private static final fixture.CustomCipher IMPL"));
        assertTrue(instance.contains("String result = IMPL.decrypt(value, key)"));
        assertTrue(instance.contains("return result.intern()"));

        String statik = GenerateStringDecryptorTask.renderSource(
                "fixture", "Bridge", "fixture.CustomCipher", true);
        assertFalse(statik.contains(" IMPL "));
        assertTrue(statik.contains("fixture.CustomCipher.decrypt(value, key)"));
    }
}
