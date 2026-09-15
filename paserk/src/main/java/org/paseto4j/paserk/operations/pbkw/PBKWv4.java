/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pbkw;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.paseto4j.commons.ByteUtils.concat;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Objects;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.operations.Crypto;

/** Password-based key wrapping for PASERK version 4. */
public final class PBKWv4 {

  private static final byte ENCRYPTION_DOMAIN = (byte) 0xff;
  private static final byte AUTHENTICATION_DOMAIN = (byte) 0xfe;
  private static final int LOCAL_LENGTH = 32;
  private static final int SECRET_LENGTH = 64;

  private final SecureRandom random;

  public PBKWv4() {
    this(new SecureRandom());
  }

  public PBKWv4(SecureRandom random) {
    this.random = Objects.requireNonNull(random);
  }

  public String wrapLocal(byte[] key, byte[] password, V4PasswordOptions options) {
    requireLength(key, LOCAL_LENGTH);
    return wrap(key, password, options, "k4.local-pw.");
  }

  public byte[] unwrapLocal(String paserk, byte[] password, PasswordLimits limits) {
    return unwrap(paserk, password, limits, "k4.local-pw.", LOCAL_LENGTH);
  }

  public String wrapSecret(byte[] key, byte[] password, V4PasswordOptions options) {
    requireLength(key, SECRET_LENGTH);
    return wrap(key, password, options, "k4.secret-pw.");
  }

  public byte[] unwrapSecret(String paserk, byte[] password, PasswordLimits limits) {
    return unwrap(paserk, password, limits, "k4.secret-pw.", SECRET_LENGTH);
  }

  private String wrap(
      byte[] key, byte[] password, V4PasswordOptions options, String header) {
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(options, "options");
    byte[] salt = new byte[16];
    byte[] nonce = new byte[24];
    random.nextBytes(salt);
    random.nextBytes(nonce);
    byte[] memory = Util.longToBytes(options.memoryBytes());
    byte[] iterations = Util.intToBytes(options.iterations());
    byte[] parallelism = Util.intToBytes(options.parallelism());
    byte[] preKey =
        Crypto.argon2id(
            password,
            salt,
            Math.toIntExact(options.memoryBytes() / 1024),
            options.iterations(),
            options.parallelism(),
            32);
    byte[] encryptionKey =
        Crypto.blake2b(32, concat(new byte[] {ENCRYPTION_DOMAIN}, preKey));
    byte[] authenticationKey =
        Crypto.blake2b(32, concat(new byte[] {AUTHENTICATION_DOMAIN}, preKey));
    byte[] encryptedKey = Crypto.xChaCha20(key, encryptionKey, nonce);
    byte[] tag =
        Crypto.blake2b(
            32,
            concat(
                header.getBytes(US_ASCII),
                salt,
                memory,
                iterations,
                parallelism,
                nonce,
                encryptedKey),
            authenticationKey);
    byte[] output =
        concat(salt, memory, iterations, parallelism, nonce, encryptedKey, tag);
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
    if (wrapped.length != 88 + plaintextLength) {
      throw new PaserkException("Invalid password-wrapped key length");
    }
    byte[] salt = Util.slice(wrapped, 0, 16);
    byte[] memoryBytes = Util.slice(wrapped, 16, 8);
    byte[] iterationBytes = Util.slice(wrapped, 24, 4);
    byte[] parallelismBytes = Util.slice(wrapped, 28, 4);
    byte[] nonce = Util.slice(wrapped, 32, 24);
    byte[] encryptedKey = Util.slice(wrapped, 56, plaintextLength);
    byte[] tag = Util.slice(wrapped, 56 + plaintextLength, 32);
    long memory = Util.bytesToLong(memoryBytes);
    int iterations = Util.bytesToInt(iterationBytes);
    int parallelism = Util.bytesToInt(parallelismBytes);
    validateParameters(memory, iterations, parallelism, limits);
    byte[] preKey =
        Crypto.argon2id(
            password,
            salt,
            Math.toIntExact(memory / 1024),
            iterations,
            parallelism,
            32);
    byte[] authenticationKey =
        Crypto.blake2b(32, concat(new byte[] {AUTHENTICATION_DOMAIN}, preKey));
    byte[] expectedTag =
        Crypto.blake2b(
            32,
            concat(
                header.getBytes(US_ASCII),
                salt,
                memoryBytes,
                iterationBytes,
                parallelismBytes,
                nonce,
                encryptedKey),
            authenticationKey);
    if (!MessageDigest.isEqual(tag, expectedTag)) {
      Util.wipe(preKey, authenticationKey, expectedTag);
      throw new PaserkException("Invalid password or wrapped key");
    }
    byte[] encryptionKey =
        Crypto.blake2b(32, concat(new byte[] {ENCRYPTION_DOMAIN}, preKey));
    byte[] plaintext = Crypto.xChaCha20(encryptedKey, encryptionKey, nonce);
    Util.wipe(preKey, authenticationKey, expectedTag, encryptionKey);
    requireLength(plaintext, plaintextLength);
    return plaintext;
  }

  private static void validateParameters(
      long memory, int iterations, int parallelism, PasswordLimits limits) {
    if (memory <= 0
        || memory > limits.maxMemoryBytes()
        || memory % 1024 != 0
        || memory / 1024 > Integer.MAX_VALUE) {
      throw new PaserkException("Argon2 memory exceeds the configured limit");
    }
    if (iterations <= 0 || iterations > limits.maxIterations()) {
      throw new PaserkException("Argon2 iterations exceed the configured limit");
    }
    if (parallelism <= 0 || parallelism > limits.maxParallelism()) {
      throw new PaserkException("Argon2 parallelism exceeds the configured limit");
    }
    if (memory / 1024 < 8L * parallelism) {
      throw new PaserkException("Argon2 memory is too small for the encoded parallelism");
    }
  }

  private static void requireLength(byte[] key, int expected) {
    if (key == null || key.length != expected) {
      throw new PaserkException("Invalid key length");
    }
  }
}
