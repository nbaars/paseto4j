/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

public record SecretKey(byte[] key) {
  public SecretKey {
    if (key == null) {
      throw new PasetoException("Key must not be null");
    }
    if (key.length != 32) {
      throw new PasetoException("Key must be a byte array of length 32");
    }
  }
}
