/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V3;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

class PasetoPublic {

  private PasetoPublic() {}

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign
   */
  static String sign(
      PrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    requireNonNull(privateKey);
    requireNonNull(payload);
    verify(privateKey.isValidFor(V3, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    TokenOut token = new TokenOut(V3, PURPOSE_PUBLIC);

    // 3
    byte[] pk = publicKey(privateKey);
    verify(pk.length == 49, "`pk` **MUST** be 49 bytes long");
    verify(
        pk[0] == (byte) 0x02 || pk[0] == (byte) 0x03,
        "The first byte **MUST** be `0x02` or `0x03`");
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            pk,
            token.header(),
            payload.getBytes(UTF_8),
            footer.getBytes(UTF_8),
            implicitAssertion.getBytes(UTF_8));

    // 4
    byte[] signature = CryptoFunctions.sign(privateKey.getKey(), m2);
    verify(signature.length == 96, "The length of the signature **MUST** be 96 bytes long");

    // 5
    return token
        .payload(ByteUtils.concat(payload.getBytes(UTF_8), signature))
        .footer(footer)
        .doFinal();
  }

  /**
   * Parse the token,
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify
   */
  static String parse(
      PublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    verify(publicKey.isValidFor(V3, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    // 1 and 2
    Token token = new Token(signedMessage, V3, PURPOSE_PUBLIC, footer);

    // 3
    byte[] sm = getUrlDecoder().decode(token.getPayload());
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 96, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 96);

    // 4
    byte[] pk = toCompressed(publicKey);
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            pk, token.header(), message, footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

    // 5
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(PublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verify(key.getKey(), m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }

  public static byte[] publicKey(PrivateKey key) {
    if (key.getKey() instanceof ECPrivateKey) {
      return publicKeyFromPrivate(((ECPrivateKey) key.getKey()).getS());
    }
    throw new IllegalStateException("Only supported for EC");
  }

  /** ECDSA Public Key Point Compression */
  private static byte[] publicKeyFromPrivate(BigInteger privKey) {
    X9ECParameters params = SECNamedCurves.getByName("secp384r1");
    var curve =
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    ECPoint point = curve.getG().multiply(privKey);
    return point.getEncoded(true);
  }

  private static byte[] toCompressed(PublicKey key) {
    if (key.getKey() instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
      return ((org.bouncycastle.jce.interfaces.ECPublicKey) key.getKey()).getQ().getEncoded(true);
    }
    throw new IllegalStateException("Public key is not an EC public key ");
  }
}
