package com.hunter.dexcfgobf.string;

final class EncryptedString {
    final byte[] value;
    final byte[] key;
    final boolean identityCiphertext;

    EncryptedString(byte[] value, byte[] key, boolean identityCiphertext) {
        this.value = value;
        this.key = key;
        this.identityCiphertext = identityCiphertext;
    }
}
