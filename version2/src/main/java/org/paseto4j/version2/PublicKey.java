/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import java.util.Arrays;

import org.paseto4j.commons.PasetoException;

public record PublicKey(byte[] key) {
  public PublicKey {
    if (key == null || key.length != 32) {
      throw new PasetoException("Key must be a byte array of length 32");
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    PublicKey other = (PublicKey) o;
    return Arrays.equals(key, other.key);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(key);
  }

  @Override
  public String toString() {
    return "PublicKey{" + "key=" + Arrays.toString(key) + '}';
  }
}
