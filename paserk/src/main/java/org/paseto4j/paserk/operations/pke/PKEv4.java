/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pke;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.paseto4j.commons.ByteUtils.concat;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.Crypto;
import org.paseto4j.paserk.operations.PKEInterface;
import org.paseto4j.paserk.operations.key.SealingPublicKey;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

/** PASERK version 4 public-key encryption. */
public final class PKEv4 implements PKEInterface {

  private static final String HEADER = "k4.seal.";
  private static final byte ENCRYPTION_DOMAIN = 0x01;
  private static final byte AUTHENTICATION_DOMAIN = 0x02;
  private static final int KEY_LENGTH = 32;
  private static final BigInteger FIELD_PRIME = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

  private final SecureRandom random;

  public PKEv4() {
    this(new SecureRandom());
  }

  public PKEv4(SecureRandom random) {
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public Version version() {
    return Version.V4;
  }

  @Override
  public String seal(byte[] localKey, SealingPublicKey publicKey) {
    requireLocalKey(localKey);
    requireVersion(publicKey.version());
    byte[] recipientEdwards = KeyEncoding.encodeV4Public((EdECPublicKey) publicKey.key());
    byte[] recipientMontgomery = ed25519PublicToX25519(recipientEdwards);
    X25519PrivateKeyParameters ephemeralSecret = new X25519PrivateKeyParameters(random);
    byte[] ephemeralPublic = ephemeralSecret.generatePublicKey().getEncoded();
    byte[] sharedSecret = new byte[KEY_LENGTH];
    try {
      ephemeralSecret.generateSecret(
          new X25519PublicKeyParameters(recipientMontgomery), sharedSecret, 0);
    } catch (RuntimeException e) {
      throw new PaserkException("Unable to perform X25519 key agreement", e);
    }
    byte[] encryptionKey =
        derive(
            ENCRYPTION_DOMAIN,
            sharedSecret,
            ephemeralPublic,
            recipientMontgomery);
    byte[] authenticationKey =
        derive(
            AUTHENTICATION_DOMAIN,
            sharedSecret,
            ephemeralPublic,
            recipientMontgomery);
    byte[] nonce = Crypto.blake2b(24, concat(ephemeralPublic, recipientMontgomery));
    byte[] encryptedKey = Crypto.xChaCha20(localKey, encryptionKey, nonce);
    byte[] tag =
        Crypto.blake2b(
            32,
            concat(HEADER.getBytes(US_ASCII), ephemeralPublic, encryptedKey),
            authenticationKey);
    byte[] output = concat(tag, ephemeralPublic, encryptedKey);
    Util.wipe(
        recipientMontgomery,
        sharedSecret,
        encryptionKey,
        authenticationKey,
        nonce);
    return HEADER + Util.encode(output);
  }

  @Override
  public byte[] unseal(String paserk, SealingSecretKey secretKey) {
    Objects.requireNonNull(secretKey, "secretKey");
    requireVersion(secretKey.version());
    byte[] sealed = Util.decode(Util.payload(paserk, HEADER));
    if (sealed.length != 96) {
      throw new PaserkException("Invalid k4.seal payload length");
    }
    byte[] tag = Util.slice(sealed, 0, KEY_LENGTH);
    byte[] ephemeralPublic = Util.slice(sealed, KEY_LENGTH, KEY_LENGTH);
    byte[] encryptedKey = Util.slice(sealed, KEY_LENGTH * 2, KEY_LENGTH);
    byte[] secret = KeyEncoding.encodeV4Secret((EdECPrivateKey) secretKey.key());
    byte[] recipientEdwards = Arrays.copyOfRange(secret, KEY_LENGTH, KEY_LENGTH * 2);
    byte[] recipientMontgomery = ed25519PublicToX25519(recipientEdwards);
    byte[] x25519Secret = ed25519SecretToX25519(secret);
    byte[] sharedSecret = new byte[KEY_LENGTH];
    try {
      new X25519PrivateKeyParameters(x25519Secret)
          .generateSecret(new X25519PublicKeyParameters(ephemeralPublic), sharedSecret, 0);
    } catch (RuntimeException e) {
      Util.wipe(secret, x25519Secret, sharedSecret, recipientMontgomery);
      throw new PaserkException("Unable to perform X25519 key agreement", e);
    }
    byte[] authenticationKey =
        derive(
            AUTHENTICATION_DOMAIN,
            sharedSecret,
            ephemeralPublic,
            recipientMontgomery);
    byte[] expectedTag =
        Crypto.blake2b(
            32,
            concat(HEADER.getBytes(US_ASCII), ephemeralPublic, encryptedKey),
            authenticationKey);
    if (!MessageDigest.isEqual(tag, expectedTag)) {
      Util.wipe(
          secret,
          x25519Secret,
          sharedSecret,
          recipientMontgomery,
          authenticationKey,
          expectedTag);
      throw new PaserkException("Invalid sealed-key authentication tag");
    }
    byte[] encryptionKey =
        derive(
            ENCRYPTION_DOMAIN,
            sharedSecret,
            ephemeralPublic,
            recipientMontgomery);
    byte[] nonce = Crypto.blake2b(24, concat(ephemeralPublic, recipientMontgomery));
    byte[] localKey = Crypto.xChaCha20(encryptedKey, encryptionKey, nonce);
    Util.wipe(
        secret,
        x25519Secret,
        sharedSecret,
        recipientMontgomery,
        authenticationKey,
        expectedTag,
        encryptionKey,
        nonce);
    return localKey;
  }

  private static byte[] derive(
      byte domain, byte[] sharedSecret, byte[] ephemeralPublic, byte[] recipientPublic) {
    return Crypto.blake2b(
        32,
        concat(
            new byte[] {domain},
            HEADER.getBytes(US_ASCII),
            sharedSecret,
            ephemeralPublic,
            recipientPublic));
  }

  private static byte[] ed25519PublicToX25519(byte[] encoded) {
    byte[] yBytes = encoded.clone();
    yBytes[31] &= 0x7f;
    reverse(yBytes);
    BigInteger y = new BigInteger(1, yBytes);
    if (y.compareTo(FIELD_PRIME) >= 0) {
      throw new PaserkException("Invalid Ed25519 sealing public key");
    }
    BigInteger denominator = BigInteger.ONE.subtract(y).mod(FIELD_PRIME);
    if (denominator.signum() == 0) {
      throw new PaserkException("Ed25519 sealing public key cannot be converted to X25519");
    }
    BigInteger u =
        BigInteger.ONE
            .add(y)
            .multiply(denominator.modInverse(FIELD_PRIME))
            .mod(FIELD_PRIME);
    byte[] bigEndian = unsignedBigEndian(u, KEY_LENGTH);
    reverse(bigEndian);
    return bigEndian;
  }

  private static byte[] ed25519SecretToX25519(byte[] secret) {
    byte[] digest;
    try {
      digest = MessageDigest.getInstance("SHA-512").digest(Arrays.copyOf(secret, KEY_LENGTH));
    } catch (NoSuchAlgorithmException e) {
      throw new PaserkException("SHA-512 is unavailable", e);
    }
    byte[] scalar = Arrays.copyOf(digest, KEY_LENGTH);
    scalar[0] &= (byte) 248;
    scalar[31] &= (byte) 127;
    scalar[31] |= (byte) 64;
    Util.wipe(digest);
    return scalar;
  }

  private static byte[] unsignedBigEndian(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    int offset = encoded.length > 1 && encoded[0] == 0 ? 1 : 0;
    int encodedLength = encoded.length - offset;
    if (encodedLength > length) {
      throw new PaserkException("Invalid X25519 public-key coordinate");
    }
    byte[] result = new byte[length];
    System.arraycopy(encoded, offset, result, length - encodedLength, encodedLength);
    return result;
  }

  private static void reverse(byte[] bytes) {
    for (int left = 0, right = bytes.length - 1; left < right; left++, right--) {
      byte value = bytes[left];
      bytes[left] = bytes[right];
      bytes[right] = value;
    }
  }

  private static void requireLocalKey(byte[] key) {
    if (key == null || key.length != KEY_LENGTH) {
      throw new PaserkException("A local key must be exactly 32 bytes");
    }
  }

  private static void requireVersion(Version version) {
    if (version != Version.V4) {
      throw new PaserkException("A k4.seal operation requires a version 4 sealing key");
    }
  }
}
