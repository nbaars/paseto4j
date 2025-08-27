/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.paseto4j.commons.Hex;
import org.paseto4j.commons.PasetoException;

class PrivateKeyTest {

  // Test vector with 64 bytes (128 hex chars)
  private static final String VALID_KEY_HEX =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" +
      "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

  private static final byte[] VALID_KEY_BYTES = new byte[64];

  static {
    // Initialize test vector with recognizable pattern
    for (int i = 0; i < VALID_KEY_BYTES.length; i++) {
      VALID_KEY_BYTES[i] = (byte) (i + 0x70); // Starting from ASCII 'p'
    }
  }

  @Test
  void constructorAcceptsValidHex() {
    // Given a valid 64-byte hex
    Hex validHex = new Hex(VALID_KEY_BYTES);

    // When creating a PrivateKey
    PrivateKey privateKey = new PrivateKey(validHex);

    // Then it should be created successfully and contain the correct bytes
    assertNotNull(privateKey);
    assertArrayEquals(VALID_KEY_BYTES, privateKey.toBytes());
  }

  @Test
  void constructorRejectsNullHex() {
    // When/Then creating a PrivateKey with null should throw exception
    assertThrows(PasetoException.class, () -> new PrivateKey(null));
  }

  @Test
  void constructorRejectsInvalidLengthHex() {
    // Given a hex of incorrect length (32 bytes)
    Hex shortHex = new Hex(new byte[32]);

    // When/Then creating a PrivateKey should throw exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> new PrivateKey(shortHex)
    );

    // And the exception should mention the correct length
    assertTrue(exception.getMessage().contains("64 bytes"));
  }

  @Test
  void fromBytesCreatesValidKey() {
    // When creating from valid bytes
    PrivateKey privateKey = PrivateKey.fromBytes(VALID_KEY_BYTES);

    // Then it should return the correct key
    assertNotNull(privateKey);
    assertArrayEquals(VALID_KEY_BYTES, privateKey.toBytes());
  }

  @Test
  void fromBytesRejectsNullInput() {
    // When/Then creating from null bytes should throw exception
    assertThrows(PasetoException.class, () -> PrivateKey.fromBytes(null));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 32, 63, 65, 128})
  void fromBytesRejectsInvalidLength(int length) {
    // Given byte array of incorrect length
    byte[] invalidLengthBytes = new byte[length];

    // When/Then creating PrivateKey should throw exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> PrivateKey.fromBytes(invalidLengthBytes)
    );

    // And the exception should mention the correct length
    assertTrue(exception.getMessage().contains("64"));
  }

  @Test
  void fromHexStringCreatesValidKey() {
    // When creating from valid hex string
    PrivateKey privateKey = PrivateKey.fromHexString(VALID_KEY_HEX);

    // Then it should create the key correctly
    assertNotNull(privateKey);
    assertArrayEquals(VALID_KEY_BYTES, privateKey.toBytes());
  }

  @Test
  void fromHexStringRejectsInvalidHex() {
    // Given invalid hex characters
    String invalidHex = "ZZZZ" + VALID_KEY_HEX.substring(4);

    // When/Then creating from invalid hex should throw exception
    assertThrows(IllegalArgumentException.class, () -> PrivateKey.fromHexString(invalidHex));
  }

  @Test
  void fromHexStringRejectsInvalidLength() {
    // Given hex string of incorrect length (32 bytes)
    String shortHex = VALID_KEY_HEX.substring(0, 64);

    // When/Then creating PrivateKey should throw exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> PrivateKey.fromHexString(shortHex)
    );

    // And the exception should mention the correct length
    assertTrue(exception.getMessage().contains("64 bytes"));
  }

  @Test
  void toBytesReturnsCopy() {
    // Given a private key
    PrivateKey privateKey = new PrivateKey(new Hex(VALID_KEY_BYTES));

    // When getting bytes twice
    byte[] bytes1 = privateKey.toBytes();
    byte[] bytes2 = privateKey.toBytes();

    // Then they should be equal but different instances
    assertArrayEquals(bytes1, bytes2);
    assertNotSame(bytes1, bytes2);

    // And modifying one should not affect the other
    bytes1[0] = (byte) (bytes1[0] + 1);
    assertNotEquals(bytes1[0], bytes2[0]);
  }

  @Test
  void toStringHidesKeyMaterial() {
    // Given a private key
    PrivateKey privateKey = new PrivateKey(new Hex(VALID_KEY_BYTES));

    // When getting string representation
    String stringRep = privateKey.toString();

    // Then it should be masked
    assertEquals("****", stringRep);

    // And should not contain actual key material
    assertFalse(stringRep.contains(VALID_KEY_HEX));
  }

  @Test
  void equalsAndHashCodeWorkCorrectly() {
    // Given two identical keys
    PrivateKey key1 = PrivateKey.fromBytes(VALID_KEY_BYTES);
    PrivateKey key2 = PrivateKey.fromBytes(VALID_KEY_BYTES.clone());

    // Then they should be equal and have same hash code
    assertEquals(key1, key2);
    assertEquals(key1.hashCode(), key2.hashCode());

    // And a key from hex string should also be equal
    PrivateKey key3 = PrivateKey.fromHexString(VALID_KEY_HEX);
    assertEquals(key1, key3);
    assertEquals(key1.hashCode(), key3.hashCode());

    // But a different key should not be equal
    byte[] differentBytes = VALID_KEY_BYTES.clone();
    differentBytes[0] = (byte) (differentBytes[0] + 1);
    PrivateKey differentKey = PrivateKey.fromBytes(differentBytes);
    assertNotEquals(key1, differentKey);
  }
}
