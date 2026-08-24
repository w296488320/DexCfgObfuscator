package com.hunter.dexcfgobf.string;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class StreamXorStringCipherTest {

    @Test
    public void everyCipherByteDiffersEvenWhenRawStreamByteIsZero() {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = new byte[512];
        Arrays.fill(plaintext, (byte) 0x5A);

        byte[] ciphertext = StreamXorStringCipher.apply(plaintext, key);

        int state = 0x6D2B79F5;
        for (byte b : key) state = (state * 33) ^ (b & 0xff);
        boolean exercisedZeroMask = false;
        for (int i = 0; i < plaintext.length; i++) {
            state ^= state << 13;
            state ^= state >>> 17;
            state ^= state << 5;
            if ((state & 0xff) == 0) exercisedZeroMask = true;
            assertNotEquals("cipher byte must differ at index " + i,
                    plaintext[i], ciphertext[i]);
        }
        assertTrue("fixture must exercise the old zero-mask identity case", exercisedZeroMask);
        assertArrayEquals(plaintext, StreamXorStringCipher.apply(ciphertext, key));
    }

    @Test
    public void stringEncryptDecryptRemainsSymmetric() {
        StreamXorStringCipher cipher = new StreamXorStringCipher();
        byte[] key = new byte[]{0, 1, 2, 3, (byte) 0xFF};
        String plaintext = "built-in-stream-cipher-中文-🙂";

        byte[] ciphertext = cipher.encrypt(plaintext, key);

        byte[] utf8 = plaintext.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < utf8.length; i++) {
            assertNotEquals("cipher byte must differ at index " + i, utf8[i], ciphertext[i]);
        }
        assertEquals(plaintext, cipher.decrypt(ciphertext, key));
    }
}
