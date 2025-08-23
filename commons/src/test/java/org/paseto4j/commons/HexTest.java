package org.paseto4j.commons;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HexTest {

  @Test
  void createFromValidHexString() {
    // Given a valid hex string
    String hexString = "deadbeef";

    // When creating a Hex object
    Hex hex = new Hex(hexString);

    // Then the hexValue is stored correctly (in lowercase)
    assertEquals(hexString, hex.hexValue());

    // And the length is correct (half of the hex string length)
    assertEquals(4, hex.length());
  }

  @Test
  void createFromUppercaseHexString() {
    // Given a valid uppercase hex string
    String hexString = "DEADBEEF";

    // When creating a Hex object
    Hex hex = new Hex(hexString);

    // Then the hexValue is converted to lowercase
    assertEquals("deadbeef", hex.hexValue());
  }

  @Test
  void createFromMixedCaseHexString() {
    // Given a valid mixed-case hex string
    String hexString = "DeAdBeEf";

    // When creating a Hex object
    Hex hex = new Hex(hexString);

    // Then the hexValue is converted to lowercase
    assertEquals("deadbeef", hex.hexValue());
  }

  @Test
  void createFromByteArray() {
    // Given a byte array
    byte[] bytes = {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef};

    // When creating a Hex object from bytes
    Hex hex = new Hex(bytes);

    // Then the hexValue represents those bytes
    assertEquals("deadbeef", hex.hexValue());
  }

  @Test
  void factoryMethodOf() {
    // Given a byte array
    byte[] bytes = {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef};

    // When using the factory method
    Hex hex = Hex.of(bytes);

    // Then the hexValue represents those bytes
    assertEquals("deadbeef", hex.hexValue());
  }

  @Test
  void factoryMethodFromString() {
    // Given a valid hex string
    String hexString = "deadbeef";

    // When using the factory method
    Hex hex = Hex.fromString(hexString);

    // Then the hexValue is stored correctly
    assertEquals(hexString, hex.hexValue());
  }

  @Test
  void convertToBytes() {
    // Given a Hex object
    Hex hex = new Hex("deadbeef");

    // When converting to bytes
    byte[] bytes = hex.toBytes();

    // Then the bytes match the expected values
    assertArrayEquals(new byte[] {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef}, bytes);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "00", "ff", "deadbeef", "0123456789abcdef"})
  void lengthMethodReturnsCorrectByteLength(String hexString) {
    // Given a Hex object with a hex string
    Hex hex = new Hex(hexString);

    // When checking the length
    int length = hex.length();

    // Then the length is half the string length (each byte is represented by two hex chars)
    assertEquals(hexString.length() / 2, length);
  }

  @Test
  void equalsAndHashCode() {
    // Given two Hex objects with the same value
    Hex hex1 = new Hex("deadbeef");
    Hex hex2 = new Hex("deadbeef");
    Hex hex3 = new Hex("DEADBEEF"); // Uppercase, but should be equal after normalization

    // When comparing equality
    // Then they should be equal and have the same hash code
    assertEquals(hex1, hex2);
    assertEquals(hex1.hashCode(), hex2.hashCode());
    assertEquals(hex1, hex3);
    assertEquals(hex1.hashCode(), hex3.hashCode());

    // Given a different Hex object
    Hex differentHex = new Hex("cafe");

    // Then it should not be equal
    assertNotEquals(hex1, differentHex);
  }

  @Test
  void throwsExceptionForInvalidHexString() {
    // Given invalid hex strings
    // Then creating a Hex object should throw an exception
    assertThrows(IllegalArgumentException.class, () -> new Hex("xyz"));
    assertThrows(IllegalArgumentException.class, () -> new Hex("123")); // Odd length
    assertThrows(IllegalArgumentException.class, () -> new Hex("123g"));
  }

  @Test
  void throwsExceptionForNullInput() {
    // Given null inputs
    // Then creating a Hex object should throw an exception
    assertThrows(NullPointerException.class, () -> new Hex((String) null));
    assertThrows(NullPointerException.class, () -> new Hex((byte[]) null));
  }

  @Test
  void toStringShowsHexValue() {
    // Given a Hex object
    Hex hex = new Hex("deadbeef");

    // When calling toString
    String result = hex.toString();

    // Then it should contain the hex value
    assertTrue(result.contains("deadbeef"));
  }
}
