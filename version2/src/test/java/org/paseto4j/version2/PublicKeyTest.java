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

class PublicKeyTest {

  private static final byte[] VALID_KEY_BYTES = new byte[32]; // All zeros for simplicity
  private static final String VALID_HEX_STRING = "0000000000000000000000000000000000000000000000000000000000000000";

  @Test
  void constructWithValidHex() {
    // Given a valid 32-byte hex
    Hex validHex = new Hex(VALID_KEY_BYTES);

    // When creating a PublicKey
    PublicKey publicKey = new PublicKey(validHex);

    // Then it should be created successfully
    assertNotNull(publicKey);
    assertEquals(validHex, publicKey.key());
  }

  @Test
  void constructWithInvalidHexLength() {
    // Given an invalid hex (wrong length)
    Hex invalidHex = new Hex(new byte[31]); // 31 bytes instead of 32

    // When/Then creating a PublicKey should throw an exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> new PublicKey(invalidHex)
    );

    assertTrue(exception.getMessage().contains("32 bytes"));
  }

  @Test
  void constructWithNullHex() {
    // When/Then creating a PublicKey with null should throw an exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> new PublicKey(null)
    );

    assertTrue(exception.getMessage().contains("null"));
  }

  @Test
  void fromBytesWithValidKey() {
    // Given valid 32-byte array
    byte[] validKey = VALID_KEY_BYTES;

    // When creating a PublicKey using fromBytes
    PublicKey publicKey = PublicKey.fromBytes(validKey);

    // Then it should be created successfully
    assertNotNull(publicKey);
    assertArrayEquals(validKey, publicKey.toBytes());
  }

  @Test
  void fromBytesWithNullKey() {
    // When/Then creating a PublicKey from null bytes should throw an exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> PublicKey.fromBytes(null)
    );

    assertTrue(exception.getMessage().contains("null"));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 16, 31, 33, 64})
  void fromBytesWithInvalidLength(int length) {
    // Given byte array with invalid length
    byte[] invalidKey = new byte[length];

    // When/Then creating a PublicKey with invalid length should throw an exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> PublicKey.fromBytes(invalidKey)
    );

    assertTrue(exception.getMessage().contains("32"));
  }

  @Test
  void fromHexStringWithValidString() {
    // Given a valid hex string representing 32 bytes
    String validHexString = VALID_HEX_STRING;

    // When creating a PublicKey using fromHexString
    PublicKey publicKey = PublicKey.fromHexString(validHexString);

    // Then it should be created successfully
    assertNotNull(publicKey);
    assertEquals(validHexString, publicKey.key().hexValue());
  }

  @Test
  void fromHexStringWithInvalidString() {
    // Given an invalid hex string (contains non-hex characters)
    String invalidHexString = "ZZZZ0000000000000000000000000000000000000000000000000000000000";

    // When/Then creating a PublicKey with invalid hex should throw an exception
    assertThrows(
        IllegalArgumentException.class,
        () -> PublicKey.fromHexString(invalidHexString)
    );
  }

  @Test
  void fromHexStringWithInvalidLength() {
    // Given a hex string with incorrect length (30 bytes instead of 32)
    String shortHexString = "000000000000000000000000000000000000000000000000000000000000";

    // When/Then creating a PublicKey with wrong length should throw an exception
    PasetoException exception = assertThrows(
        PasetoException.class,
        () -> PublicKey.fromHexString(shortHexString)
    );

    assertTrue(exception.getMessage().contains("32 bytes"));
  }

  @Test
  void toBytesReturnsCorrectValue() {
    // Given a PublicKey created from known bytes
    byte[] originalBytes = new byte[32];
    // Fill with recognizable pattern
    for (int i = 0; i < originalBytes.length; i++) {
        originalBytes[i] = (byte) i;
    }
    PublicKey publicKey = PublicKey.fromBytes(originalBytes);

    // When getting bytes back
    byte[] retrievedBytes = publicKey.toBytes();

    // Then they should match the original bytes
    assertArrayEquals(originalBytes, retrievedBytes);

    // And modifying the returned array shouldn't affect the PublicKey
    retrievedBytes[0] = 99;
    assertNotEquals(retrievedBytes[0], publicKey.toBytes()[0]);
  }

  @Test
  void equalsAndHashCodeWorkCorrectly() {
    // Given two PublicKeys with the same content
    PublicKey key1 = PublicKey.fromBytes(VALID_KEY_BYTES);
    PublicKey key2 = PublicKey.fromBytes(VALID_KEY_BYTES);

    // Then they should be equal and have the same hash code
    assertEquals(key1, key2);
    assertEquals(key1.hashCode(), key2.hashCode());

    // Given a different PublicKey
    byte[] differentBytes = new byte[32];
    differentBytes[0] = 1; // Make it different from VALID_KEY_BYTES
    PublicKey differentKey = PublicKey.fromBytes(differentBytes);

    // Then it should not be equal
    assertNotEquals(key1, differentKey);
  }

  @Test
  void toStringContainsHexRepresentation() {
    // Given a PublicKey
    PublicKey publicKey = PublicKey.fromHexString(VALID_HEX_STRING);

    // When getting the string representation
    String stringRepresentation = publicKey.toString();

    // Then it should contain the hex representation of the key
    assertTrue(stringRepresentation.contains(VALID_HEX_STRING));
  }
}
