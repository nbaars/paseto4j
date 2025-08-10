/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.util.Arrays;
import java.util.Objects;

public record SecretKey(byte[] key) {
  public SecretKey {
    if (key == null) {
      throw new PasetoException("Key must not be null");
    }
    if (key.length != 32) {
      throw new PasetoException("Key must be a byte array of length 32");
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    SecretKey other = (SecretKey) o;
    return Arrays.equals(key, other.key);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(key);
  }

  @Override
  public String toString() {
    return "SecretKey{" + "key=****" + '}';
  }
}
