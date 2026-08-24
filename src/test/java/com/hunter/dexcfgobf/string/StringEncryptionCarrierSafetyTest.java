package com.hunter.dexcfgobf.string;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class StringEncryptionCarrierSafetyTest {
    @Test
    public void rejectsPlaintextReturnedAsKeyWithoutEchoingValue() {
        String secret = "key-leak-secret";
        StringEncryptionContext context = context(new StreamXorStringCipher(),
                new PlaintextKeyGenerator(), StringEncryptionMode.BYTES);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.encrypt(secret, "fixture/Carrier", "fixture/Carrier->value()V#0"));

        assertTrue(failure.getMessage().contains("key generator returned plaintext bytes"));
        assertFalse(failure.getMessage().contains(secret));
    }

    @Test
    public void rejectsNonIdentityCiphertextContainingWholePlaintextInBase64Mode() {
        String secret = "embedded-plaintext-secret";
        StringEncryptionContext context = context(new WrappedPlaintextCipher(),
                new FixedKeyGenerator(), StringEncryptionMode.BASE64);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.encrypt(secret, "fixture/Carrier", "fixture/Carrier->value()V#0"));

        assertTrue(failure.getMessage().contains("contains the complete plaintext byte sequence"));
        assertFalse(failure.getMessage().contains(secret));
    }

    private static StringEncryptionContext context(StringCipher cipher,
                                                   StringKeyGenerator keyGenerator,
                                                   StringEncryptionMode mode) {
        String implementation = cipher instanceof StreamXorStringCipher
                ? null : cipher.getClass().getName();
        return StringEncryptionContext.create(cipher, implementation, keyGenerator,
                Collections.singletonList("fixture"), Collections.emptyList(),
                "fixture.RuntimeBridge", mode, 7L, 4096,
                false, true, false, false, true);
    }

    private static final class PlaintextKeyGenerator implements StringKeyGenerator {
        @Override
        public byte[] generate(String value, String location) {
            return value.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static final class FixedKeyGenerator implements StringKeyGenerator {
        @Override
        public byte[] generate(String value, String location) {
            return new byte[]{3, 1, 4, 1, 5, 9, 2, 6};
        }
    }

    public static final class WrappedPlaintextCipher implements StringCipher {
        @Override
        public byte[] encrypt(String value, byte[] key) {
            byte[] plain = value.getBytes(StandardCharsets.UTF_8);
            byte[] wrapped = Arrays.copyOf(plain, plain.length + 2);
            System.arraycopy(wrapped, 0, wrapped, 1, plain.length);
            wrapped[0] = 0x5a;
            wrapped[wrapped.length - 1] = (byte) 0xa5;
            return wrapped;
        }

        @Override
        public String decrypt(byte[] value, byte[] key) {
            return new String(value, 1, value.length - 2, StandardCharsets.UTF_8);
        }
    }
}
