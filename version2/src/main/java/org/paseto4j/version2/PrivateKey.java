/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import org.paseto4j.commons.PasetoException;

import java.util.Arrays;

public record PrivateKey(byte[] key) {
  public PrivateKey {
    if (key == null) {
      throw new PasetoException("Key must not be null");
    }
    if (key.length != 64) {
      throw new PasetoException("Key must be a byte array of length 64");
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    PrivateKey other = (PrivateKey) o;
    return Arrays.equals(key, other.key);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(key);
  }

  @Override
  public String toString() {
    return "PrivateKey{" + "key=****" + '}';
  }
}
