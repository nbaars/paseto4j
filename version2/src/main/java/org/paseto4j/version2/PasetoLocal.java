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
import static java.util.Base64.getUrlEncoder;
import static java.util.Objects.requireNonNull;
import static org.apache.tuweni.bytes.Bytes.*;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.sodium.GenericHash;
import org.apache.tuweni.crypto.sodium.XChaCha20Poly1305;
import org.paseto4j.commons.*;

class PasetoLocal {

  private PasetoLocal() {}

  private static final String LOCAL = "v2.local.";

  /**
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
   */
  static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, Bytes.random(XChaCha20Poly1305.Nonce.length()).toArray(), payload, footer);
  }

  /**
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
   */
  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);
    verify(
        key.isValidFor(Version.V2, Purpose.PURPOSE_LOCAL),
        "Key is not valid for purpose and version");
    verify(key.hasLength(32), "key should be 32 bytes");

    // 3
    byte[] nonce =
        GenericHash.hash(
                24,
                GenericHash.Input.fromBytes(payload.getBytes(UTF_8)),
                GenericHash.Key.fromBytes(randomKey))
            .bytesArray();

    // 4
    byte[] preAuth =
        PreAuthenticationEncoder.encode(LOCAL.getBytes(UTF_8), nonce, footer.getBytes(UTF_8));

    // 5
    byte[] cipherText =
        XChaCha20Poly1305.encrypt(
            payload.getBytes(UTF_8),
            preAuth,
            XChaCha20Poly1305.Key.fromBytes(key.material),
            XChaCha20Poly1305.Nonce.fromBytes(nonce));

    // 6
    String signedToken =
        LOCAL
            + getUrlEncoder()
                .withoutPadding()
                .encodeToString(concatenate(wrap(nonce), wrap(cipherText)).toArray());

    if (!isNullOrEmpty(footer)) {
      signedToken =
          signedToken
              + "."
              + Base64.getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
    }
    return signedToken;
  }

  /**
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#decrypt
   */
  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);

    verify(
        key.isValidFor(Version.V2, Purpose.PURPOSE_LOCAL),
        "Key is not valid for purpose and version");

    String[] tokenParts = token.split("\\.");
    verify(
        tokenParts.length == 3 || tokenParts.length == 4, "Token should contain at least 3 parts");

    // 1
    if (!isNullOrEmpty(footer)) {
      verify(
          MessageDigest.isEqual(fromBase64String(tokenParts[3]).toArray(), footer.getBytes(UTF_8)),
          "footer does not match");
    }

    // 2
    verify(token.startsWith(LOCAL), "Token should start with " + LOCAL);

    // 3
    byte[] ct = Base64.getUrlDecoder().decode(tokenParts[2]);
    byte[] nonce = Arrays.copyOfRange(ct, 0, XChaCha20Poly1305.Nonce.length());
    byte[] encryptedMessage = Arrays.copyOfRange(ct, XChaCha20Poly1305.Nonce.length(), ct.length);

    // 4
    byte[] preAuth =
        PreAuthenticationEncoder.encode(LOCAL.getBytes(UTF_8), nonce, footer.getBytes(UTF_8));

    // 5
    byte[] message =
        XChaCha20Poly1305.decrypt(
            encryptedMessage,
            preAuth,
            XChaCha20Poly1305.Key.fromBytes(key.material),
            XChaCha20Poly1305.Nonce.fromBytes(nonce));

    return new String(message, UTF_8);
  }
}
