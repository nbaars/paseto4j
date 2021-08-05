package org.paseto4j.commons;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConditionsTest {

    @Test
    void verifyFailure() {
        assertThrows(PasetoException.class, () -> Conditions.verify(false, "Test"));
    }

    @Test
    void verifySuccess() {
        assertDoesNotThrow(() -> Conditions.verify(true, "Test"));
    }

}