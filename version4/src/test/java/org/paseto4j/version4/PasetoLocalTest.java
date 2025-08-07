/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;

import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.Version;

class PasetoLocalTest {
  private static Stream<Arguments> testVectors() throws IOException {
    return TestVectors.v4(Purpose.PURPOSE_LOCAL).stream()
        .map(
            test ->
                Arguments.of(
                    test.name,
                    test.expectFail,
                    test.key,
                    test.nonce,
                    test.payload,
                    test.footer,
                    test.implicitAssertion,
                    test.token));
  }

  @ParameterizedTest
  @MethodSource("testVectors")
  void encryptTestVectors(
      String name,
      boolean expectFail,
      String key,
      String nonce,
      String payload,
      String footer,
      String implicitAssertion,
      String expectedToken) {
    if (expectFail) {
      assertThrows(
          Exception.class,
          () ->
              PasetoLocal.encrypt(
                  new SecretKey(hexToBytes(key), Version.V4),
                  hexToBytes(nonce),
                  payload,
                  footer,
                  implicitAssertion));
    } else {
      assertEquals(
          expectedToken,
          PasetoLocal.encrypt(
              new SecretKey(hexToBytes(key), Version.V4),
              hexToBytes(nonce),
              payload,
              footer,
              implicitAssertion));
    }
  }

  @ParameterizedTest
  @MethodSource("testVectors")
  void decryptTestVectors(
      String name,
      boolean expectFail,
      String key,
      String nonce,
      String payload,
      String footer,
      String implicitAssertion,
      String encryptedToken) {
    if (expectFail) {
      assertThrows(
          Exception.class,
          () ->
              PasetoLocal.encrypt(
                  new SecretKey(hexToBytes(key), Version.V4),
                  hexToBytes(nonce),
                  payload,
                  footer,
                  implicitAssertion));
    } else {
      assertEquals(
          payload,
          PasetoLocal.decrypt(
              new SecretKey(hexToBytes(key), Version.V4),
              encryptedToken,
              footer,
              implicitAssertion));
    }
  }
}
