/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

class PasetoPublic {

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private PasetoPublic() {}

  static String sign(PrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);
    verify(privateKey.hasLength(64), "key should be 32 bytes");
    verify(privateKey.isValidFor(V2, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    TokenOut token = new TokenOut(V2, PURPOSE_PUBLIC);

    byte[] m2 = encode(token.header(), payload.getBytes(UTF_8), footer.getBytes(UTF_8));
    byte[] signature = new byte[64];
    byte[] sk = Arrays.copyOf(privateKey.getMaterial(), 64);
    SODIUM.cryptoSignDetached(signature, m2, m2.length, sk);

    return token.payload(concat(payload.getBytes(UTF_8), signature)).footer(footer).doFinal();
  }

  static String parse(PublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    verify(publicKey.hasLength(32), "key should be 32 bytes");
    verify(publicKey.isValidFor(V2, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    Token pasetoToken = new Token(signedMessage, V2, PURPOSE_PUBLIC, footer);

    // 3
    byte[] sm = getUrlDecoder().decode(pasetoToken.getPayload());
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

    // 4
    byte[] m2 =
        PreAuthenticationEncoder.encode(pasetoToken.header(), message, footer.getBytes(UTF_8));

    // 5
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(PublicKey key, byte[] message, byte[] signature)
      throws SignatureException {
    byte[] pk = Arrays.copyOf(key.getMaterial(), 32);
    boolean valid = SODIUM.cryptoSignVerifyDetached(signature, message, message.length, pk);
    if (!valid) {
      throw new SignatureException("Invalid signature");
    }
  }
}
