/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.util.Locale;
import java.util.Objects;

/**
 * An immutable representation of binary data using a hexadecimal string for storage. This class
 * provides a better alternative to using byte arrays in records and ensures proper equals,
 * hashCode, and toString behavior.
 */
public record Hex(String hexValue) {

  /** Creates a new Hex instance with validation. */
  public Hex {
    Objects.requireNonNull(hexValue, "Hex string cannot be null");
    HexToBytes.hexToBytes(hexValue);
    hexValue = hexValue.toLowerCase(Locale.ROOT);
  }

  /**
   * Creates a new Hex instance from a byte array.
   *
   * @param bytes the byte array to convert to hexadecimal
   */
  public Hex(byte[] bytes) {
    this(HexToBytes.hexEncode(Objects.requireNonNull(bytes, "Bytes cannot be null")));
  }

  /**
   * Returns the bytes represented by this Hex object.
   *
   * @return a new byte array containing the bytes
   */
  public byte[] toBytes() {
    return HexToBytes.hexToBytes(hexValue);
  }

  /**
   * Factory method to create a Hex instance from a byte array.
   *
   * @param bytes the byte array to convert
   * @return a new Hex instance
   */
  public static Hex of(byte[] bytes) {
    return new Hex(bytes);
  }

  /**
   * Factory method to create a Hex instance from a hexadecimal string.
   *
   * @param hexString the hexadecimal string
   * @return a new Hex instance
   * @throws IllegalArgumentException if the string is not valid hexadecimal
   */
  public static Hex fromString(String hexString) {
    return new Hex(hexString);
  }

  /**
   * Returns the length of the byte array representation.
   *
   * @return the length in bytes
   */
  public int length() {
    return hexValue.length() / 2;
  }
}
