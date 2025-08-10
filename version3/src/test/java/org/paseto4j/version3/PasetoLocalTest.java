/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;

import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;

class PasetoLocalTest {

  private static Stream<Arguments> testVectors() throws IOException {
    return TestVectors.v3(Purpose.PURPOSE_LOCAL).stream()
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
                  new SecretKey(hexToBytes(key)),
                  hexToBytes(nonce),
                  payload,
                  footer,
                  implicitAssertion));
    } else {
      assertEquals(
          expectedToken,
          PasetoLocal.encrypt(
              new SecretKey(hexToBytes(key)),
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
                  new SecretKey(hexToBytes(key)),
                  hexToBytes(nonce),
                  payload,
                  footer,
                  implicitAssertion));
    } else {
      assertEquals(
          payload,
          Paseto.decrypt(
              new SecretKey(hexToBytes(key)),
              encryptedToken,
              footer,
              implicitAssertion));
    }
  }

  @Test
  void normalUsage() {
    SecretKey key =
        new SecretKey(
            hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
        );
    String encryptedToken =
        Paseto.encrypt(
            key,
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");

    String token =
        PasetoLocal.decrypt(
            key, encryptedToken, "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");

    assertEquals(
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", token);
  }

  @Test
  void wrongFooter() {
    SecretKey key =
        new SecretKey(
            hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
        );
    String encryptedToken =
        Paseto.encrypt(
            key,
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "Test case footer");

    assertThrows(
        PasetoException.class,
        () -> Paseto.decrypt(key, encryptedToken, "Wrong footer"),
        "Wrong footer");
  }
}
