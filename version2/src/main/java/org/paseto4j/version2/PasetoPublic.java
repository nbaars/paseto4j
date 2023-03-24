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

package org.paseto4j.version2;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V2;

import java.security.SignatureException;
import java.util.Arrays;
import org.apache.tuweni.crypto.sodium.Signature;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

class PasetoPublic {

  private PasetoPublic() {}

  static String sign(PrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);
    verify(privateKey.hasLength(64), "key should be 32 bytes");
    verify(privateKey.isValidFor(V2, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    TokenOut token = new TokenOut(V2, PURPOSE_PUBLIC);

    byte[] m2 = encode(token.header(), payload.getBytes(UTF_8), footer.getBytes(UTF_8));
    byte[] signature =
        Signature.signDetached(m2, Signature.SecretKey.fromBytes(privateKey.getMaterial()));

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
    boolean valid =
        Signature.verifyDetached(
            message, signature, Signature.PublicKey.fromBytes(key.getMaterial()));
    if (!valid) {
      throw new SignatureException("Invalid signature");
    }
  }
}
