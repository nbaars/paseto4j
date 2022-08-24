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

package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.version1.CryptoFunctions.*;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.*;

class PasetoLocal {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String LOCAL = "v1.local.";

  private PasetoLocal() {}

  /**
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#encrypt
   */
  public static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, randomBytes(), payload, footer);
  }

  /**
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#encrypt
   */
  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);
    verify(
        key.isValidFor(Version.V1, Purpose.PURPOSE_LOCAL),
        "Key is not valid for purpose and version");

    // 3
    byte[] nonce = getNonce(payload.getBytes(UTF_8), randomKey);

    // 4
    byte[] ek = encryptionKey(key, nonce);
    byte[] ak = authenticationKey(key, nonce);

    // 5
    byte[] cipherText =
        encryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), payload.getBytes(UTF_8));

    // 6
    byte[] preAuth =
        PreAuthenticationEncoder.encode(
            LOCAL.getBytes(UTF_8), nonce, cipherText, footer.getBytes(UTF_8));

    // 7
    byte[] t = hmac384(ak, preAuth);

    // 8
    String signedToken =
        LOCAL
            + getUrlEncoder()
                .withoutPadding()
                .encodeToString(ByteUtils.concat(nonce, cipherText, t));

    if (!isNullOrEmpty(footer)) {
      signedToken =
          signedToken
              + "."
              + Base64.getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
    }
    return signedToken;
  }

  private static byte[] getNonce(byte[] payload, byte[] randomKey) {
    return Arrays.copyOfRange(CryptoFunctions.hmac384(randomKey, payload), 0, 32);
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    return hkdfSha384(
        key.material, Arrays.copyOfRange(nonce, 0, 16), "paseto-encryption-key".getBytes(UTF_8));
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    return hkdfSha384(
        key.material, Arrays.copyOfRange(nonce, 0, 16), "paseto-auth-key-for-aead".getBytes(UTF_8));
  }

  /**
   * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt
   */
  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);
    verify(
        key.isValidFor(Version.V1, Purpose.PURPOSE_LOCAL),
        "Key is not valid for purpose and version");

    String[] tokenParts = token.split("\\.");
    verify(
        tokenParts.length == 3 || tokenParts.length == 4, "Token should contain at least 3 parts");

    // 1
    if (!isNullOrEmpty(footer)) {
      verify(
          MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)),
          "footer does not match");
    }

    // 2
    verify(token.startsWith(LOCAL), "Token should start with " + LOCAL);

    // 3
    byte[] ct = getUrlDecoder().decode(tokenParts[2]);
    byte[] nonce = Arrays.copyOfRange(ct, 0, 32);
    byte[] t = Arrays.copyOfRange(ct, ct.length - 48, ct.length);
    byte[] c = Arrays.copyOfRange(ct, 32, ct.length - 48);

    // 4
    byte[] ek = encryptionKey(key, nonce);
    byte[] ak = authenticationKey(key, nonce);

    // 5
    byte[] preAuth =
        PreAuthenticationEncoder.encode(LOCAL.getBytes(UTF_8), nonce, c, footer.getBytes(UTF_8));

    // 6
    byte[] t2 = hmac384(ak, preAuth);

    // 7
    if (!MessageDigest.isEqual(t, t2)) {
      throw new IllegalStateException("HMAC verification failed");
    }

    // 8
    byte[] message = decryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), c);
    return new String(message, UTF_8);
  }
}
