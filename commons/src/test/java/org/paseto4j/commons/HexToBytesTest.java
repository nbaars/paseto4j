/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HexToBytesTest {

  @ParameterizedTest
  @MethodSource("validHexStringsProvider")
  void hexToBytesConvertsValidHexStrings(String hexString, byte[] expectedBytes) {
    // When converting to bytes
    byte[] result = HexToBytes.hexToBytes(hexString);

    // Then the bytes match the expected values
    assertArrayEquals(expectedBytes, result);
  }

  static Stream<Arguments> validHexStringsProvider() {
    return Stream.of(
        // Standard lowercase
        Arguments.of("deadbeef", new byte[]{(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef}),
        // Uppercase
        Arguments.of("DEADBEEF", new byte[]{(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef}),
        // Mixed case
        Arguments.of("DeAdBeEf", new byte[]{(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef})
    );
  }

  @Test
  void hexToBytesHandlesEmptyString() {
    // Given an empty hex string
    String hexString = "";

    // When converting to bytes
    byte[] result = HexToBytes.hexToBytes(hexString);

    // Then an empty byte array is returned
    assertEquals(0, result.length);
  }

  @ParameterizedTest
  @ValueSource(strings = {"xyz", "12Z", "G1"})
  void hexToBytesThrowsExceptionForInvalidHexCharacters(String invalidHex) {
    // When converting invalid hex, then exception is thrown
    assertThrows(IllegalArgumentException.class, () -> HexToBytes.hexToBytes(invalidHex));
  }

  @Test
  void hexToBytesThrowsExceptionForOddLength() {
    // Given a hex string with odd length
    String oddLengthHex = "abc";

    // When converting to bytes, then exception is thrown
    assertThrows(IllegalArgumentException.class, () -> HexToBytes.hexToBytes(oddLengthHex));
  }

  @Test
  void hexEncodeTurnsEmptyByteArrayToEmptyString() {
    // Given an empty byte array
    byte[] emptyBytes = new byte[0];

    // When encoding to hex
    String result = HexToBytes.hexEncode(emptyBytes);

    // Then an empty string is returned
    assertEquals("", result);
  }

  @Test
  void hexEncodeTurnsBytesToLowercaseHexString() {
    // Given a byte array
    byte[] bytes = {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef};

    // When encoding to hex
    String result = HexToBytes.hexEncode(bytes);

    // Then the correct lowercase hex string is returned
    assertEquals("deadbeef", result);
  }

  @Test
  void hexEncodeHandlesAllByteValues() {
    // Given a byte array with all possible byte values
    byte[] allBytes = new byte[256];
    for (int i = 0; i < 256; i++) {
      allBytes[i] = (byte) i;
    }

    // When encoding to hex
    String result = HexToBytes.hexEncode(allBytes);

    // Then verify the result is correct and has the expected length
    assertEquals(512, result.length()); // 256 bytes * 2 hex chars per byte

    // Check some sample values
    assertTrue(result.startsWith("000102")); // First bytes: 0, 1, 2
    assertTrue(result.endsWith("fdfeff")); // Last bytes: 253, 254, 255
  }

  @Test
  void roundTripConversionPreservesData() {
    // Given original bytes
    byte[] original = {
      0x00, 0x01, 0x02, (byte) 0xff, (byte) 0xfe, (byte) 0xfd, 0x7f, (byte) 0x80, 0x3a, 0x29
    };

    // When converting to hex and back
    String hex = HexToBytes.hexEncode(original);
    byte[] roundTrip = HexToBytes.hexToBytes(hex);

    // Then the round-trip data matches the original
    assertArrayEquals(original, roundTrip);
  }

  @Test
  void roundTripConversionPreservesString() {
    // Given original hex string
    String original = "0123456789abcdef";

    // When converting to bytes and back
    byte[] bytes = HexToBytes.hexToBytes(original);
    String roundTrip = HexToBytes.hexEncode(bytes);

    // Then the round-trip string matches the original (in lowercase)
    assertEquals(original, roundTrip);
  }
}
