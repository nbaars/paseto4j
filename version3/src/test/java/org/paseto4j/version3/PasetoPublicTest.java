/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.TestVectors;

class PasetoPublicTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static KeyPair readEC(String pem) throws IOException {
    Reader rdr = new StringReader(pem);
    Object parsed = new PEMParser(rdr).readObject();
    return new JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair) parsed);
  }

  public static String writeToPEM(java.security.PrivateKey privateKey) throws IOException {
    var writer = new StringWriter();
    try (var pemWriter = new PemWriter(writer)) {
      var pki = PrivateKeyInfo.getInstance(ASN1Sequence.getInstance(privateKey.getEncoded()));
      ASN1Object asn = (ASN1Object) pki.parsePrivateKey();
      pemWriter.writeObject(new PemObject("EC PRIVATE KEY", asn.getEncoded("DER")));
      pemWriter.flush();
      return writer.toString();
    }
  }

  @ParameterizedTest
  @MethodSource("testVectors")
  void signTestVectors(
      String name,
      boolean expectFail,
      String privateKeyPem,
      String payload,
      String footer,
      String implicitAssertion,
      String expectedToken)
      throws IOException, SignatureException {
    var keyPair = readEC(privateKeyPem);
    var privateKey = (ECPrivateKey) keyPair.getPrivate();
    var publicKey = (ECPublicKey) keyPair.getPublic();
    if (expectFail) {
      assertThrows(
          Exception.class, () -> Paseto.sign(privateKey, payload, footer, implicitAssertion));
    } else {
      assertEquals(expectedToken, Paseto.sign(privateKey, payload, footer, implicitAssertion));
      assertEquals(payload, Paseto.parse(publicKey, expectedToken, footer, implicitAssertion));
    }
  }

  private static Stream<Arguments> testVectors() throws IOException {
    return TestVectors.v3(Purpose.PURPOSE_PUBLIC).stream()
        .map(
            test ->
                Arguments.of(
                    test.name,
                    test.expectFail,
                    test.secretKeyPem,
                    test.payload,
                    test.footer,
                    test.implicitAssertion,
                    test.token));
  }

  @Test
  void normalUsage()
      throws NoSuchAlgorithmException,
          NoSuchProviderException,
          InvalidAlgorithmParameterException,
          SignatureException {
    var generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    var spec = new ECGenParameterSpec("secp384r1");
    generator.initialize(spec);
    var expectedPayload = "test message";
    var keyPair = generator.generateKeyPair();

    var signedMessage = Paseto.sign((ECPrivateKey) keyPair.getPrivate(), expectedPayload);
    var payload = Paseto.parse((ECPublicKey) keyPair.getPublic(), signedMessage);

    Assertions.assertEquals(expectedPayload, payload);
  }

  @Test
  void signingWhereASNPartsShouldBePadded() throws IOException, SignatureException {
    var pem =
        "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDBKvAg41dsJ64e+CY5Ona1PdhkHtDXZawacdj4fcUQVqR2hy19NML7S\nWpHchEsBzCegBwYFK4EEACKhZANiAARnuVQrWJkAJ7tBA9HkSvgpyn6haQQHZ4a2\nKqJwZ6LwVujOpP4gOPaIrL0fGDR2zQSZMaggHfYemqordD9nq9oPzBwVI+KZ8Rnq\nl35zsijbS3D6g5tN1cfcxtmB9c/2KVs=\n-----END EC PRIVATE KEY-----";
    var keyPair = readEC(pem);
    var expectedPayload = "test message";

    var signedMessage = Paseto.sign((ECPrivateKey) keyPair.getPrivate(), expectedPayload);
    var payload = Paseto.parse((ECPublicKey) keyPair.getPublic(), signedMessage);

    Assertions.assertEquals(expectedPayload, payload);
  }
}
