package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

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
