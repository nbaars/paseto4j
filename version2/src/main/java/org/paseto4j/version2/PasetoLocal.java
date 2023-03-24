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
import static java.util.Objects.requireNonNull;
import static org.apache.tuweni.bytes.Bytes.concatenate;
import static org.apache.tuweni.bytes.Bytes.wrap;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V2;

import java.util.Arrays;
import java.util.Base64;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.sodium.GenericHash;
import org.apache.tuweni.crypto.sodium.XChaCha20Poly1305;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

class PasetoLocal {

  private PasetoLocal() {}

  static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, Bytes.random(XChaCha20Poly1305.Nonce.length()).toArray(), payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);
    verify(key.isValidFor(V2, PURPOSE_LOCAL), "Key is not valid for purpose and version");
    verify(key.hasLength(32), "key should be 32 bytes");

    TokenOut token = new TokenOut(V2, PURPOSE_LOCAL);

    // 3
    byte[] nonce =
        GenericHash.hash(
                24,
                GenericHash.Input.fromBytes(payload.getBytes(UTF_8)),
                GenericHash.Key.fromBytes(randomKey))
            .bytesArray();

    // 4
    byte[] preAuth = PreAuthenticationEncoder.encode(token.header(), nonce, footer.getBytes(UTF_8));

    // 5
    byte[] cipherText =
        XChaCha20Poly1305.encrypt(
            payload.getBytes(UTF_8),
            preAuth,
            XChaCha20Poly1305.Key.fromBytes(key.getMaterial()),
            XChaCha20Poly1305.Nonce.fromBytes(nonce));

    // 6
    return token
        .payload(concatenate(wrap(nonce), wrap(cipherText)).toArray())
        .footer(footer)
        .doFinal();
  }

  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);
    verify(key.isValidFor(V2, PURPOSE_LOCAL), "Key is not valid for purpose and version");

    // 1 and 2
    Token pasetoToken = new Token(token, V2, PURPOSE_LOCAL, footer);

    // 3
    byte[] ct = Base64.getUrlDecoder().decode(pasetoToken.getPayload());
    byte[] nonce = Arrays.copyOfRange(ct, 0, XChaCha20Poly1305.Nonce.length());
    byte[] encryptedMessage = Arrays.copyOfRange(ct, XChaCha20Poly1305.Nonce.length(), ct.length);

    // 4
    byte[] preAuth =
        PreAuthenticationEncoder.encode(pasetoToken.header(), nonce, footer.getBytes(UTF_8));

    // 5
    byte[] message =
        XChaCha20Poly1305.decrypt(
            encryptedMessage,
            preAuth,
            XChaCha20Poly1305.Key.fromBytes(key.getMaterial()),
            XChaCha20Poly1305.Nonce.fromBytes(nonce));

    if (message == null) {
      throw new PasetoException("Unable to decrypt the token, result was null");
    }
    return new String(message, UTF_8);
  }
}
