/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.wrap;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.paseto4j.commons.ByteUtils.concat;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.PaserkVersion;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.WrappingKey;
import org.paseto4j.paserk.operations.WrapInterface;

abstract class PieVersion implements WrapInterface {

  private static final byte ENCRYPTION_DOMAIN = (byte) 0x80;
  private static final byte AUTHENTICATION_DOMAIN = (byte) 0x81;

  private final Version version;
  private final WrappingKey wrappingKey;
  private final SecureRandom random;

  PieVersion(Version version, WrappingKey wrappingKey, SecureRandom random) {
    PaserkVersion.header(version);
    this.version = version;
    this.wrappingKey = Objects.requireNonNull(wrappingKey, "wrappingKey");
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public final Version version() {
    return version;
  }

  @Override
  public final String prefix() {
    return "pie";
  }

  @Override
  public final String wrapLocal(byte[] key) {
    requireLength(key, 32, "local");
    return wrap(key, "local-wrap");
  }

  @Override
  public final byte[] unwrapLocal(String paserk) {
    return unwrap(paserk, "local-wrap", 32);
  }

  @Override
  public final String wrapSecret(byte[] key) {
    requireLength(key, secretKeyLength(), "secret");
    return wrap(key, "secret-wrap");
  }

  @Override
  public final byte[] unwrapSecret(String paserk) {
    return unwrap(paserk, "secret-wrap", secretKeyLength());
  }

  protected abstract int encryptionMaterialLength();

  protected abstract int encryptionNonceLength();

  protected abstract int tagLength();

  protected abstract int secretKeyLength();

  protected abstract byte[] derive(int length, byte[] message, byte[] key);

  protected abstract byte[] authenticate(byte[] message, byte[] key);

  protected abstract byte[] crypt(byte[] input, byte[] key, byte[] nonce);

  private String wrap(byte[] plaintext, String type) {
    String header = header(type);
    byte[] nonce = new byte[32];
    random.nextBytes(nonce);
    byte[] wrappingKeyBytes = wrappingKey.toBytes();
    byte[] encryptionMaterial =
        derive(
            encryptionMaterialLength(),
            concat(new byte[] {ENCRYPTION_DOMAIN}, nonce),
            wrappingKeyBytes);
    byte[] encryptionKey = Arrays.copyOf(encryptionMaterial, 32);
    byte[] encryptionNonce =
        Arrays.copyOfRange(encryptionMaterial, 32, 32 + encryptionNonceLength());
    byte[] authenticationKey =
        derive(32, concat(new byte[] {AUTHENTICATION_DOMAIN}, nonce), wrappingKeyBytes);
    byte[] ciphertext = crypt(plaintext, encryptionKey, encryptionNonce);
    byte[] tag =
        authenticate(concat(header.getBytes(US_ASCII), nonce, ciphertext), authenticationKey);
    byte[] output = concat(tag, nonce, ciphertext);
    Util.wipe(wrappingKeyBytes, encryptionMaterial, encryptionKey, encryptionNonce, authenticationKey);
    return header + Util.encode(output);
  }

  private byte[] unwrap(String paserk, String type, int plaintextLength) {
    String header = header(type);
    byte[] wrapped = Util.decode(Util.payload(paserk, header));
    int expectedLength = tagLength() + 32 + plaintextLength;
    if (wrapped.length != expectedLength) {
      throw new PaserkException("Invalid wrapped key length");
    }
    byte[] tag = Util.slice(wrapped, 0, tagLength());
    byte[] nonce = Util.slice(wrapped, tagLength(), 32);
    byte[] ciphertext = Util.slice(wrapped, tagLength() + 32, plaintextLength);
    byte[] wrappingKeyBytes = wrappingKey.toBytes();
    byte[] authenticationKey =
        derive(32, concat(new byte[] {AUTHENTICATION_DOMAIN}, nonce), wrappingKeyBytes);
    byte[] expectedTag =
        authenticate(concat(header.getBytes(US_ASCII), nonce, ciphertext), authenticationKey);
    if (!MessageDigest.isEqual(tag, expectedTag)) {
      Util.wipe(wrappingKeyBytes, authenticationKey, expectedTag);
      throw new PaserkException("Invalid wrapped key authentication tag");
    }
    byte[] encryptionMaterial =
        derive(
            encryptionMaterialLength(),
            concat(new byte[] {ENCRYPTION_DOMAIN}, nonce),
            wrappingKeyBytes);
    byte[] encryptionKey = Arrays.copyOf(encryptionMaterial, 32);
    byte[] encryptionNonce =
        Arrays.copyOfRange(encryptionMaterial, 32, 32 + encryptionNonceLength());
    byte[] plaintext = crypt(ciphertext, encryptionKey, encryptionNonce);
    Util.wipe(
        wrappingKeyBytes,
        authenticationKey,
        expectedTag,
        encryptionMaterial,
        encryptionKey,
        encryptionNonce);
    return plaintext;
  }

  private String header(String type) {
    return PaserkVersion.typeHeader(version, type) + prefix() + ".";
  }

  private static void requireLength(byte[] key, int expected, String type) {
    if (key == null || key.length != expected) {
      throw new PaserkException(
          "A " + type + " key for this version must be exactly " + expected + " bytes");
    }
  }
}
