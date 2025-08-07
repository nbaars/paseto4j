/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;

import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

class PasetoPublic {

  private PasetoPublic() {}

  /**
   * Sign the token,
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign
   */
  static String sign(PrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);
    verify(privateKey.isValidFor(V1, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    TokenOut token = new TokenOut(V1, PURPOSE_PUBLIC);

    // 2
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            token.header(), payload.getBytes(UTF_8), footer.getBytes(UTF_8));

    // 3
    byte[] signature = CryptoFunctions.signRsaPssSha384(privateKey.getMaterial(), m2);

    // 4
    return token
        .payload(ByteUtils.concat(payload.getBytes(UTF_8), signature))
        .footer(footer)
        .doFinal();
  }

  /**
   * Parse the token,
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify
   */
  static String parse(PublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    verify(publicKey.isValidFor(V1, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    // 1 & 2
    Token token = new Token(signedMessage, V1, PURPOSE_PUBLIC, footer);

    // 3
    byte[] sm = getUrlDecoder().decode(token.getPayload());
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 256, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 256);

    // 4
    byte[] m2 = PreAuthenticationEncoder.encode(token.header(), message, footer.getBytes(UTF_8));

    // 5
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(PublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verifyRsaPssSha384(key.getMaterial(), m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }
}
