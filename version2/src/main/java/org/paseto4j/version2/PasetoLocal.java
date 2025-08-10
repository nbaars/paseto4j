/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.AEAD;
import java.util.Arrays;
import java.util.Base64;

import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;

class PasetoLocal {

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private PasetoLocal() {}

  static String encrypt(SecretKey key, String payload, String footer) {
    byte[] randomKey = SODIUM.randomBytesBuf(32);
    return encrypt(key, randomKey, payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);

    TokenOut token = new TokenOut(V2, PURPOSE_LOCAL);

    // 3 - Generate nonce using GenericHash
    byte[] nonce = new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES];
    byte[] payloadBytes = payload.getBytes(UTF_8);
    SODIUM.cryptoGenericHash(
        nonce, nonce.length, payloadBytes, payloadBytes.length, randomKey, randomKey.length);

    // 4 - Pre-auth encoding (unchanged)
    byte[] preAuth = PreAuthenticationEncoder.encode(token.header(), nonce, footer.getBytes(UTF_8));

    // 5 - XChaCha20Poly1305 encryption
    byte[] cipherText = new byte[payloadBytes.length + AEAD.XCHACHA20POLY1305_IETF_ABYTES];
    long[] cipherLen = new long[1];

    boolean success =
        SODIUM.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            cipherText,
            cipherLen,
            payloadBytes,
            payloadBytes.length,
            preAuth,
            preAuth.length,
            null, // No additional data
            nonce,
            key.key());

    if (!success) {
      throw new PasetoException("Encryption failed");
    }

    // 6
    return token.payload(concat(nonce, cipherText)).footer(footer).doFinal();
  }

  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);

    // 1 and 2
    Token pasetoToken = new Token(token, V2, PURPOSE_LOCAL, footer);

    // 3
    byte[] ct = Base64.getUrlDecoder().decode(pasetoToken.getPayload());
    byte[] nonce = Arrays.copyOfRange(ct, 0, AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
    byte[] encryptedMessage =
        Arrays.copyOfRange(ct, AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES, ct.length);

    // 4
    byte[] preAuth =
        PreAuthenticationEncoder.encode(pasetoToken.header(), nonce, footer.getBytes(UTF_8));

    // 5 - XChaCha20Poly1305 decryption using Lazysodium
    byte[] message = new byte[encryptedMessage.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];
    long[] messageLen = new long[1];

    boolean success =
        SODIUM.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            message,
            messageLen,
            null, // No additional data
            encryptedMessage,
            encryptedMessage.length,
            preAuth,
            preAuth.length,
            nonce,
            key.key());

    if (!success) {
      throw new PasetoException("Unable to decrypt the token");
    }

    return new String(message, 0, (int) messageLen[0], UTF_8);
  }
}
