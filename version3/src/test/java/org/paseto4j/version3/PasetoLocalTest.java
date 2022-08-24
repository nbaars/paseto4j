/*
 * MIT License
 *
 * Copyright (c) 2018 Nanne Baars
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
import org.paseto4j.commons.Version;

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
                  new SecretKey(hexToBytes(key), Version.V3),
                  hexToBytes(nonce),
                  payload,
                  footer,
                  implicitAssertion));
    } else {
      assertEquals(
          expectedToken,
          PasetoLocal.encrypt(
              new SecretKey(hexToBytes(key), Version.V3),
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
                  new SecretKey(hexToBytes(key), Version.V3),
                  hexToBytes(nonce),
                  payload,
                  footer,
                  implicitAssertion));
    } else {
      assertEquals(
          payload,
          Paseto.decrypt(
              new SecretKey(hexToBytes(key), Version.V3),
              encryptedToken,
              footer,
              implicitAssertion));
    }
  }

  @Test
  void normalUsage() {
    SecretKey key =
        new SecretKey(
            hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
            Version.V3);
    String encryptedToken =
        PasetoLocal.encrypt(
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
            hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
            Version.V3);
    String encryptedToken =
        PasetoLocal.encrypt(
            key,
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "Test case footer");

    assertThrows(
        PasetoException.class,
        () -> Paseto.decrypt(key, encryptedToken, "Wrong footer"),
        "Wrong footer");
  }
}
