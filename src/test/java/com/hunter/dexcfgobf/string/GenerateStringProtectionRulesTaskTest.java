package com.hunter.dexcfgobf.string;

import org.gradle.api.tasks.CacheableTask;
import org.junit.Test;

import java.util.Locale;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class GenerateStringProtectionRulesTaskTest {

    @Test
    public void emitsMinimalCacheableRuleForOrdinaryMarkedMethods() {
        String marker = "fixture.Bridge$ExactStringSite";
        String rules = GenerateStringProtectionRulesTask.renderRules(marker);

        assertNotNull(GenerateStringProtectionRulesTask.class.getAnnotation(CacheableTask.class));
        assertTrue(rules.contains("@" + marker + " <methods>;"));
        assertTrue(rules.contains("allowshrinking"));
        assertTrue(rules.contains("allowobfuscation"));
        assertFalse(rules.contains("allowoptimization"));
        assertFalse(rules.contains("keepattributes"));
        assertFalse(rules.contains("<clinit>"));
        assertFalse(rules.toLowerCase(Locale.ROOT).contains("stringfog"));
    }

    @Test
    public void rejectsInvalidMarkerNames() {
        assertThrows(IllegalArgumentException.class,
                () -> GenerateStringProtectionRulesTask.renderRules("not a class"));
    }
}
