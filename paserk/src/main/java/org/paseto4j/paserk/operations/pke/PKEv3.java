/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pke;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.paseto4j.commons.ByteUtils.concat;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.KeyAgreement;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.Crypto;
import org.paseto4j.paserk.operations.PKEInterface;
import org.paseto4j.paserk.operations.key.SealingPublicKey;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

/** PASERK version 3 public-key encryption. */
public final class PKEv3 implements PKEInterface {

  private static final String HEADER = "k3.seal.";
  private static final byte ENCRYPTION_DOMAIN = 0x01;
  private static final byte AUTHENTICATION_DOMAIN = 0x02;
  private static final int LOCAL_KEY_LENGTH = 32;
  private static final int PUBLIC_KEY_LENGTH = 49;
  private static final int TAG_LENGTH = 48;

  private final SecureRandom random;

  public PKEv3() {
    this(new SecureRandom());
  }

  public PKEv3(SecureRandom random) {
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public Version version() {
    return Version.V3;
  }

  @Override
  public String seal(byte[] localKey, SealingPublicKey publicKey) {
    requireLocalKey(localKey);
    requireVersion(publicKey.version());
    ECPublicKey recipient = (ECPublicKey) publicKey.key();
    KeyPair ephemeral = generateEphemeralKeyPair();
    ECPrivateKey ephemeralSecret = (ECPrivateKey) ephemeral.getPrivate();
    byte[] ephemeralPublic = KeyEncoding.encodeV3Public((ECPublicKey) ephemeral.getPublic());
    byte[] recipientPublic = KeyEncoding.encodeV3Public(recipient);
    byte[] sharedSecret = agree(ephemeralSecret, recipient);
    byte[] encryptionMaterial =
        Crypto.sha384(
            concat(
                new byte[] {ENCRYPTION_DOMAIN},
                HEADER.getBytes(US_ASCII),
                sharedSecret,
                ephemeralPublic,
                recipientPublic));
    byte[] encryptionKey = Arrays.copyOf(encryptionMaterial, 32);
    byte[] nonce = Arrays.copyOfRange(encryptionMaterial, 32, 48);
    byte[] authenticationKey =
        Crypto.sha384(
            concat(
                new byte[] {AUTHENTICATION_DOMAIN},
                HEADER.getBytes(US_ASCII),
                sharedSecret,
                ephemeralPublic,
                recipientPublic));
    byte[] encryptedKey = Crypto.aes256Ctr(localKey, encryptionKey, nonce);
    byte[] tag =
        Crypto.hmacSha384(
            authenticationKey, concat(HEADER.getBytes(US_ASCII), ephemeralPublic, encryptedKey));
    byte[] output = concat(tag, ephemeralPublic, encryptedKey);
    Util.wipe(sharedSecret, encryptionMaterial, encryptionKey, nonce, authenticationKey);
    return HEADER + Util.encode(output);
  }

  @Override
  public byte[] unseal(String paserk, SealingSecretKey secretKey) {
    Objects.requireNonNull(secretKey, "secretKey");
    requireVersion(secretKey.version());
    byte[] sealed = Util.decode(Util.payload(paserk, HEADER));
    if (sealed.length != TAG_LENGTH + PUBLIC_KEY_LENGTH + LOCAL_KEY_LENGTH) {
      throw new PaserkException("Invalid k3.seal payload length");
    }
    byte[] tag = Util.slice(sealed, 0, TAG_LENGTH);
    byte[] ephemeralPublic = Util.slice(sealed, TAG_LENGTH, PUBLIC_KEY_LENGTH);
    byte[] encryptedKey =
        Util.slice(sealed, TAG_LENGTH + PUBLIC_KEY_LENGTH, LOCAL_KEY_LENGTH);
    ECPublicKey ephemeral = KeyEncoding.decodeV3Public(ephemeralPublic);
    ECPrivateKey recipient = (ECPrivateKey) secretKey.key();
    byte[] recipientPublic = KeyEncoding.encodeV3Public(KeyEncoding.deriveV3Public(recipient));
    byte[] sharedSecret = agree(recipient, ephemeral);
    byte[] authenticationKey =
        Crypto.sha384(
            concat(
                new byte[] {AUTHENTICATION_DOMAIN},
                HEADER.getBytes(US_ASCII),
                sharedSecret,
                ephemeralPublic,
                recipientPublic));
    byte[] expectedTag =
        Crypto.hmacSha384(
            authenticationKey, concat(HEADER.getBytes(US_ASCII), ephemeralPublic, encryptedKey));
    if (!MessageDigest.isEqual(tag, expectedTag)) {
      Util.wipe(sharedSecret, authenticationKey, expectedTag);
      throw new PaserkException("Invalid sealed-key authentication tag");
    }
    byte[] encryptionMaterial =
        Crypto.sha384(
            concat(
                new byte[] {ENCRYPTION_DOMAIN},
                HEADER.getBytes(US_ASCII),
                sharedSecret,
                ephemeralPublic,
                recipientPublic));
    byte[] encryptionKey = Arrays.copyOf(encryptionMaterial, 32);
    byte[] nonce = Arrays.copyOfRange(encryptionMaterial, 32, 48);
    byte[] localKey = Crypto.aes256Ctr(encryptedKey, encryptionKey, nonce);
    Util.wipe(
        sharedSecret,
        authenticationKey,
        expectedTag,
        encryptionMaterial,
        encryptionKey,
        nonce);
    return localKey;
  }

  private KeyPair generateEphemeralKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp384r1"), random);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new PaserkException("Unable to generate an ephemeral P-384 key", e);
    }
  }

  private static byte[] agree(ECPrivateKey secretKey, ECPublicKey publicKey) {
    try {
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
      agreement.init(secretKey);
      agreement.doPhase(publicKey, true);
      byte[] sharedSecret = agreement.generateSecret();
      if (sharedSecret.length != 48) {
        throw new PaserkException("Unexpected P-384 shared-secret length");
      }
      return sharedSecret;
    } catch (GeneralSecurityException e) {
      throw new PaserkException("Unable to perform P-384 key agreement", e);
    }
  }

  private static void requireLocalKey(byte[] key) {
    if (key == null || key.length != LOCAL_KEY_LENGTH) {
      throw new PaserkException("A local key must be exactly 32 bytes");
    }
  }

  private static void requireVersion(Version version) {
    if (version != Version.V3) {
      throw new PaserkException("A k3.seal operation requires a version 3 sealing key");
    }
  }
}
