/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SecretKeyTest {

  private static final byte[] SECRET_KEY =
      HexToBytes.hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
  private static final String SECRET_KEY_HEX = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

  @Test
  void nullKeyShouldThrowException() {
    assertThrows(PasetoException.class, () -> new SecretKey(null));
  }

  @Test
  void shortKeyShouldThrowException() {
    assertThrows(PasetoException.class, () -> SecretKey.fromBytes(new byte[31]));
  }

  @Test
  void shouldAcceptValidKey() {
    var key = SecretKey.fromBytes(SECRET_KEY);
    assertArrayEquals(SECRET_KEY, key.toBytes());
  }

  @Test
  void fromHexStringShouldCreateValidKey() {
    // When creating a key from a valid hex string
    var key = SecretKey.fromHexString(SECRET_KEY_HEX);

    // Then the key should be created successfully
    assertNotNull(key);

    // And the bytes should match the expected value
    assertArrayEquals(SECRET_KEY, key.toBytes());
  }

  @Test
  void fromHexStringShouldThrowOnInvalidLength() {
    // Given an invalid hex string (wrong length)
    String shortHex = "707172737475767778797a7b7c7d7e7f80818283848586"; // 24 bytes instead of 32

    // When/Then creating a key should throw an exception
    assertThrows(PasetoException.class, () -> SecretKey.fromHexString(shortHex));
  }

  @Test
  void fromHexStringShouldThrowOnInvalidHex() {
    // Given an invalid hex string (not hex characters)
    String invalidHex = "707172737475767778797a7b7c7d7e7f8081828384858687ZZZZZZZZZZZZZZ";

    // When/Then creating a key should throw an exception
    assertThrows(IllegalArgumentException.class, () -> SecretKey.fromHexString(invalidHex));
  }

  @Test
  void toStringShouldReturnStars() {
    // Given a valid key
    var key = SecretKey.fromBytes(SECRET_KEY);

    // When converting to string
    String result = key.toString();

    // Then it should return masked value for security
    assertEquals("****", result);
  }

  @Test
  void equalsAndHashCodeShouldWork() {
    // Given two keys with the same content
    var key1 = SecretKey.fromBytes(SECRET_KEY);
    var key2 = SecretKey.fromBytes(SECRET_KEY.clone());

    // Then they should be equal and have the same hash code
    assertEquals(key1, key2);
    assertEquals(key1.hashCode(), key2.hashCode());

    // And a key created from hex string should also be equal
    var key3 = SecretKey.fromHexString(SECRET_KEY_HEX);
    assertEquals(key1, key3);
    assertEquals(key1.hashCode(), key3.hashCode());
  }

  @Test
  void differentKeysShouldNotBeEqual() {
    // Given two different keys
    var key1 = SecretKey.fromBytes(SECRET_KEY);

    byte[] differentKey = SECRET_KEY.clone();
    differentKey[0] = (byte) (differentKey[0] + 1); // Change one byte
    var key2 = SecretKey.fromBytes(differentKey);

    // Then they should not be equal
    assertNotEquals(key1, key2);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 16, 31, 33, 64})
  void invalidLengthsShouldThrowException(int length) {
    // Given key bytes with invalid length
    byte[] invalidKey = new byte[length];

    // When/Then creating a key should throw an exception
    assertThrows(PasetoException.class, () -> SecretKey.fromBytes(invalidKey));
  }
}
