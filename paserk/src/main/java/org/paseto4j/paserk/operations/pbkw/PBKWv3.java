/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pbkw;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.paseto4j.commons.ByteUtils.concat;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.operations.Crypto;

/** Password-based key wrapping for PASERK version 3. */
public final class PBKWv3 {

  private static final byte ENCRYPTION_DOMAIN = (byte) 0xff;
  private static final byte AUTHENTICATION_DOMAIN = (byte) 0xfe;
  private static final int LOCAL_LENGTH = 32;
  private static final int SECRET_LENGTH = 48;

  private final SecureRandom random;

  public PBKWv3() {
    this(new SecureRandom());
  }

  public PBKWv3(SecureRandom random) {
    this.random = Objects.requireNonNull(random);
  }

  public String wrapLocal(byte[] key, byte[] password, V3PasswordOptions options) {
    requireLength(key, LOCAL_LENGTH);
    return wrap(key, password, options, "k3.local-pw.");
  }

  public byte[] unwrapLocal(String paserk, byte[] password, PasswordLimits limits) {
    return unwrap(paserk, password, limits, "k3.local-pw.", LOCAL_LENGTH);
  }

  public String wrapSecret(byte[] key, byte[] password, V3PasswordOptions options) {
    requireLength(key, SECRET_LENGTH);
    return wrap(key, password, options, "k3.secret-pw.");
  }

  public byte[] unwrapSecret(String paserk, byte[] password, PasswordLimits limits) {
    return unwrap(paserk, password, limits, "k3.secret-pw.", SECRET_LENGTH);
  }

  private String wrap(
      byte[] key, byte[] password, V3PasswordOptions options, String header) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(options, "options");
    byte[] salt = new byte[32];
    byte[] nonce = new byte[16];
    random.nextBytes(salt);
    random.nextBytes(nonce);
    byte[] iterations = Util.intToBytes(options.iterations());
    byte[] preKey = Crypto.pbkdf2Sha384(password, salt, options.iterations(), 32);
    byte[] encryptionKey =
        Arrays.copyOf(Crypto.sha384(concat(new byte[] {ENCRYPTION_DOMAIN}, preKey)), 32);
    byte[] authenticationKey =
        Crypto.sha384(concat(new byte[] {AUTHENTICATION_DOMAIN}, preKey));
    byte[] encryptedKey = Crypto.aes256Ctr(key, encryptionKey, nonce);
    byte[] tag =
        Crypto.hmacSha384(
            authenticationKey,
            concat(header.getBytes(US_ASCII), salt, iterations, nonce, encryptedKey));
    byte[] output = concat(salt, iterations, nonce, encryptedKey, tag);
    Util.wipe(preKey, encryptionKey, authenticationKey);
    return header + Util.encode(output);
  }

  private byte[] unwrap(
      String paserk,
      byte[] password,
      PasswordLimits limits,
      String header,
      int plaintextLength) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(limits, "limits");
    byte[] wrapped = Util.decode(Util.payload(paserk, header));
    if (wrapped.length != 100 + plaintextLength) {
      throw new PaserkException("Invalid password-wrapped key length");
    }
    byte[] salt = Util.slice(wrapped, 0, 32);
    byte[] iterationBytes = Util.slice(wrapped, 32, 4);
    byte[] nonce = Util.slice(wrapped, 36, 16);
    byte[] encryptedKey = Util.slice(wrapped, 52, plaintextLength);
    byte[] tag = Util.slice(wrapped, 52 + plaintextLength, 48);
    int iterations = Util.bytesToInt(iterationBytes);
    if (iterations <= 0 || iterations > limits.maxIterations()) {
      throw new PaserkException("PBKDF2 iterations exceed the configured limit");
    }
    byte[] preKey = Crypto.pbkdf2Sha384(password, salt, iterations, 32);
    byte[] authenticationKey =
        Crypto.sha384(concat(new byte[] {AUTHENTICATION_DOMAIN}, preKey));
    byte[] expectedTag =
        Crypto.hmacSha384(
            authenticationKey,
            concat(header.getBytes(US_ASCII), salt, iterationBytes, nonce, encryptedKey));
    if (!MessageDigest.isEqual(tag, expectedTag)) {
      Util.wipe(preKey, authenticationKey, expectedTag);
      throw new PaserkException("Invalid password or wrapped key");
    }
    byte[] encryptionKey =
        Arrays.copyOf(Crypto.sha384(concat(new byte[] {ENCRYPTION_DOMAIN}, preKey)), 32);
    byte[] plaintext = Crypto.aes256Ctr(encryptedKey, encryptionKey, nonce);
    Util.wipe(preKey, authenticationKey, expectedTag, encryptionKey);
    requireLength(plaintext, plaintextLength);
    return plaintext;
  }

  private static void requireLength(byte[] key, int expected) {
    if (key == null || key.length != expected) {
      throw new PaserkException("Invalid key length");
    }
  }
}
