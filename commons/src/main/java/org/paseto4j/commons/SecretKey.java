/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * An immutable representation of a secret key used in PASETO operations. Uses Hex for internal
 * storage to ensure proper equals, hashCode, and toString behavior.
 */
public record SecretKey(Hex key) {
  /**
   * Creates a new SecretKey with the given Hex key.
   *
   * @param key the key material as a Hex object
   * @throws PasetoException if the key is null or not 32 bytes in length
   */
  public SecretKey {
    if (key == null) {
      throw new PasetoException("Key must not be null");
    }
    if (key.length() != 32) {
      throw new PasetoException("Key must be 32 bytes in length");
    }
  }

  /**
   * Creates a new SecretKey with the given byte array.
   *
   * @param keyBytes the key material as a byte array
   * @return a new SecretKey instance
   * @throws PasetoException if the key is null or not 32 bytes in length
   */
  public static SecretKey fromBytes(byte[] keyBytes) {
    if (keyBytes == null) {
      throw new PasetoException("Key must not be null");
    }
    if (keyBytes.length != 32) {
      throw new PasetoException("Key must be a byte array of length 32");
    }
    return new SecretKey(new Hex(keyBytes));
  }

  public static SecretKey fromHexString(String key) {
    return new SecretKey(Hex.fromString(key));
  }

  /**
   * Returns the key material as a byte array.
   *
   * @return a new byte array containing the key material
   */
  public byte[] toBytes() {
    return key.toBytes();
  }

  @Override
  public String toString() {
    return "SecretKey{key=****}";
  }
}
