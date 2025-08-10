/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.Version.V4;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.stream.Stream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.TestVectors;

public class PasetoPublicTest {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static Stream<Arguments> testVectors() throws IOException {
    return TestVectors.v4(Purpose.PURPOSE_PUBLIC).stream()
        .map(
            test ->
                Arguments.of(
                    test.name,
                    test.expectFail,
                    test.publicKeyPem,
                    test.secretKeyPem,
                    test.payload,
                    test.footer,
                    test.implicitAssertion,
                    test.token));
  }

  @ParameterizedTest
  @MethodSource("testVectors")
  void signTestVectors(
      String name,
      boolean expectFail,
      String publicKeyPem,
      String secretKeyPem,
      String payload,
      String footer,
      String implicitAssertion,
      String expectedToken)
      throws IOException, SignatureException {
    Reader rdr = new StringReader(secretKeyPem);
    Object parsed = new PEMParser(rdr).readObject();
    var privateKey =
        (EdECPrivateKey) new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) parsed);

    if (expectFail) {
      assertThrows(
          Exception.class, () -> PasetoPublic.sign(privateKey, payload, footer, implicitAssertion));
    } else {
      assertEquals(
          expectedToken, PasetoPublic.sign(privateKey, payload, footer, implicitAssertion));
    }
  }

  @ParameterizedTest
  @MethodSource("testVectors")
  void parseTestVectors(
      String name,
      boolean expectFail,
      String publicKeyPem,
      String secretKeyPem,
      String payload,
      String footer,
      String implicitAssertion,
      String expectedToken)
      throws IOException, SignatureException {
    Reader rdr = new StringReader(publicKeyPem);
    Object parsed = new PEMParser(rdr).readObject();
    var publicKey =
        (EdECPublicKey) new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) parsed);

    if (expectFail) {
      assertThrows(
          Exception.class,
          () -> PasetoPublic.parse(publicKey, expectedToken, footer, implicitAssertion));
    } else {
      assertEquals(
          payload, PasetoPublic.parse(publicKey, expectedToken, footer, implicitAssertion));
    }
  }
}
