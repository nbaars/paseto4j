/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import org.paseto4j.commons.Conditions;
import org.paseto4j.commons.Hex;
import org.paseto4j.commons.PasetoException;

/**
 * An immutable representation of a public key used in PASETO v2 operations. Uses Hex for internal
 * storage to ensure proper equals, hashCode, and toString behavior.
 */
public record PublicKey(Hex key) {
  /**
   * Creates a new PublicKey with the given Hex key.
   *
   * @param key the key material as a Hex object
   * @throws PasetoException if the key is null or not 32 bytes in length
   */
  public PublicKey {
    Conditions.verify(key != null, "Key must not be null");
    Conditions.verify(key.length() == 32, "Key must be 32 bytes in length");
  }

  /**
   * Creates a new PublicKey with the given byte array.
   *
   * @param keyBytes the key material as a byte array
   * @return a new PublicKey instance
   * @throws PasetoException if the key is null or not 32 bytes in length
   */
  public static PublicKey fromBytes(byte[] keyBytes) {
    Conditions.verify(keyBytes != null, "Key must not be null");
    Conditions.verify(keyBytes.length == 32, "Key must be a byte array of length 32");

    return new PublicKey(new Hex(keyBytes));
  }

  /**
   * Creates a new PublicKey from a hexadecimal string representation.
   *
   * @param hexString the hexadecimal string representation of the key
   * @return a new PublicKey instance
   * @throws PasetoException if the resulting key is not 32 bytes in length
   * @throws IllegalArgumentException if the string is not valid hexadecimal
   */
  public static PublicKey fromHexString(String hexString) {
    Hex hex = Hex.fromString(hexString);
    Conditions.verify(hex.length() == 32, "Key must be 32 bytes in length");

    return new PublicKey(hex);
  }

  /**
   * Returns the key material as a byte array.
   *
   * @return a new byte array containing the key material
   */
  public byte[] toBytes() {
    return key.toBytes();
  }
}
