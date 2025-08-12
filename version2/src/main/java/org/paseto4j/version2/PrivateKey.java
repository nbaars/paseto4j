/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import org.paseto4j.commons.Hex;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.Conditions;

/**
 * Represents a private key for use with PASETO Version 2 tokens. This class is immutable and
 * thread-safe.
 */
public record PrivateKey(Hex key) {
  public PrivateKey {
    Conditions.verify(key != null, "Key must not be null");
    Conditions.verify(key.length() == 64, "Key must be 64 bytes in length");
  }

  /**
   * Creates a new PrivateKey with the given byte array.
   *
   * @param keyBytes the key material as a byte array
   * @return a new PrivateKey instance
   * @throws PasetoException if the key is null or not 64 bytes in length
   */
  public static PrivateKey fromBytes(byte[] keyBytes) {
    Conditions.verify(keyBytes != null, "Key must not be null");
    Conditions.verify(keyBytes.length == 64, "Key must be a byte array of length 64");
    return new PrivateKey(new Hex(keyBytes));
  }

  /**
   * Creates a new PrivateKey from a hexadecimal string representation.
   *
   * @param hexString the hexadecimal string representation of the key
   * @return a new PrivateKey instance
   * @throws PasetoException if the resulting key is not 64 bytes in length
   * @throws IllegalArgumentException if the string is not valid hexadecimal
   */
  public static PrivateKey fromHexString(String hexString) {
    Hex hex = Hex.fromString(hexString);
    Conditions.verify(hex.length() == 64, "Key must be 64 bytes in length");
    return new PrivateKey(hex);
  }

  /**
   * Returns the key as a byte array.
   *
   * @return a new byte array containing the key
   */
  public byte[] toBytes() {
    return key.toBytes();
  }

  @Override
  public String toString() {
    return "****";
  }
}
