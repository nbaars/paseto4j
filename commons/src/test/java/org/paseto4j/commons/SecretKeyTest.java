/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SecretKeyTest {

  private static final byte[] SECRET_KEY =
      HexToBytes.hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");

  @Test
  void nullKeyShouldThrowException() {
    Assertions.assertThrows(PasetoException.class, () -> new SecretKey(null));
  }

  @Test
  void shortKeyShouldThrowException() {
    Assertions.assertThrows(PasetoException.class, () -> SecretKey.fromBytes(new byte[31]));
  }

  @Test
  void shouldAcceptValidKey() {
    var key = SecretKey.fromBytes(SECRET_KEY);
    Assertions.assertArrayEquals(SECRET_KEY, key.toBytes());
  }
}
