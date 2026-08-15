package com.hunter.dexcfgobf.gradle;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ObfuscationLevelTest {

    @Test
    public void exposesStableLevelsAndDefaultsToMedium() {
        assertEquals(1, ObfuscationLevel.LOW.getDepth());
        assertEquals(2, ObfuscationLevel.MEDIUM.getDepth());
        assertEquals(3, ObfuscationLevel.HIGH.getDepth());

        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension();
        assertTrue(extension.getEnabled());
        assertEquals(ObfuscationLevel.MEDIUM, extension.getLevel());
    }
}
