/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.keys;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.paseto4j.paserk.PaserkException;

/** Converts between JCA keys and the raw key encodings required by PASERK. */
public final class KeyEncoding {

  private static final String P384 = "secp384r1";
  private static final int P384_BYTES = 48;
  private static final int ED25519_BYTES = 32;

  private KeyEncoding() {}

  public static byte[] encodeV3Secret(ECPrivateKey key) {
    requireP384(key.getParams());
    return unsignedBigEndian(key.getS(), P384_BYTES);
  }

  public static ECPrivateKey decodeV3Secret(byte[] encoded) {
    if (encoded.length != P384_BYTES) {
      throw new PaserkException("A k3.secret key must be 48 bytes");
    }
    BigInteger scalar = new BigInteger(1, encoded);
    ECParameterSpec parameters = p384Parameters();
    if (scalar.signum() <= 0 || scalar.compareTo(parameters.getOrder()) >= 0) {
      throw new PaserkException("Invalid P-384 secret scalar");
    }
    try {
      return (ECPrivateKey)
          KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(scalar, parameters));
    } catch (GeneralSecurityException e) {
      throw new PaserkException("Unable to decode P-384 secret key", e);
    }
  }

  public static byte[] encodeV3Public(ECPublicKey key) {
    requireP384(key.getParams());
    var parameters = SECNamedCurves.getByName(P384);
    var point =
        parameters
            .getCurve()
            .createPoint(key.getW().getAffineX(), key.getW().getAffineY())
            .normalize();
    if (point.isInfinity() || !point.isValid()) {
      throw new PaserkException("Invalid P-384 public key");
    }
    return point.getEncoded(true);
  }

  public static ECPublicKey decodeV3Public(byte[] encoded) {
    if (encoded.length != P384_BYTES + 1 || (encoded[0] != 0x02 && encoded[0] != 0x03)) {
      throw new PaserkException("A k3.public key must be a compressed P-384 point");
    }
    try {
      var parameters = SECNamedCurves.getByName(P384);
      var point = parameters.getCurve().decodePoint(encoded).normalize();
      if (point.isInfinity() || !point.isValid()) {
        throw new PaserkException("Invalid P-384 public key");
      }
      var jcaPoint =
          new java.security.spec.ECPoint(
              point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());
      return (ECPublicKey)
          KeyFactory.getInstance("EC")
              .generatePublic(new ECPublicKeySpec(jcaPoint, p384Parameters()));
    } catch (IllegalArgumentException | GeneralSecurityException e) {
      throw new PaserkException("Unable to decode P-384 public key", e);
    }
  }

  public static ECPublicKey deriveV3Public(ECPrivateKey key) {
    requireP384(key.getParams());
    var parameters = SECNamedCurves.getByName(P384);
    return decodeV3Public(parameters.getG().multiply(key.getS()).normalize().getEncoded(true));
  }

  public static byte[] encodeV4Secret(EdECPrivateKey key) {
    requireEd25519(key.getParams().getName());
    byte[] seed =
        key.getBytes()
            .orElseThrow(() -> new PaserkException("Ed25519 private key is not extractable"));
    if (seed.length != ED25519_BYTES) {
      throw new PaserkException("An Ed25519 seed must be 32 bytes");
    }
    byte[] publicKey = new Ed25519PrivateKeyParameters(seed).generatePublicKey().getEncoded();
    byte[] encoded = new byte[ED25519_BYTES * 2];
    System.arraycopy(seed, 0, encoded, 0, ED25519_BYTES);
    System.arraycopy(publicKey, 0, encoded, ED25519_BYTES, ED25519_BYTES);
    Arrays.fill(seed, (byte) 0);
    return encoded;
  }

  public static EdECPrivateKey decodeV4Secret(byte[] encoded) {
    validateV4Secret(encoded);
    byte[] seed = Arrays.copyOf(encoded, ED25519_BYTES);
    try {
      return (EdECPrivateKey)
          KeyFactory.getInstance("Ed25519")
              .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
    } catch (GeneralSecurityException e) {
      throw new PaserkException("Unable to decode Ed25519 secret key", e);
    } finally {
      Arrays.fill(seed, (byte) 0);
    }
  }

  public static byte[] encodeV4Public(EdECPublicKey key) {
    requireEd25519(key.getParams().getName());
    byte[] encoded = littleEndian(key.getPoint().getY(), ED25519_BYTES);
    if (key.getPoint().isXOdd()) {
      encoded[ED25519_BYTES - 1] |= (byte) 0x80;
    }
    return encoded;
  }

  public static EdECPublicKey decodeV4Public(byte[] encoded) {
    if (encoded.length != ED25519_BYTES) {
      throw new PaserkException("A k4.public key must be exactly 32 bytes");
    }
    byte[] yBytes = encoded.clone();
    boolean xOdd = (yBytes[ED25519_BYTES - 1] & 0x80) != 0;
    yBytes[ED25519_BYTES - 1] &= 0x7f;
    BigInteger y = unsignedLittleEndian(yBytes);
    try {
      return (EdECPublicKey)
          KeyFactory.getInstance("Ed25519")
              .generatePublic(
                  new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
    } catch (GeneralSecurityException e) {
      throw new PaserkException("Unable to decode Ed25519 public key", e);
    }
  }

  public static EdECPublicKey deriveV4Public(EdECPrivateKey key) {
    byte[] secret = encodeV4Secret(key);
    try {
      return decodeV4Public(Arrays.copyOfRange(secret, ED25519_BYTES, 64));
    } finally {
      Arrays.fill(secret, (byte) 0);
    }
  }

  public static void validateV4Secret(byte[] encoded) {
    if (encoded.length != ED25519_BYTES * 2) {
      throw new PaserkException("A k4.secret key must be 64 bytes");
    }
    byte[] seed = Arrays.copyOf(encoded, ED25519_BYTES);
    byte[] expected = new Ed25519PrivateKeyParameters(seed).generatePublicKey().getEncoded();
    byte[] actual = Arrays.copyOfRange(encoded, ED25519_BYTES, ED25519_BYTES * 2);
    Arrays.fill(seed, (byte) 0);
    if (!java.security.MessageDigest.isEqual(expected, actual)) {
      throw new PaserkException("Ed25519 secret and public key components do not match");
    }
  }

  public static void validateV4SealingPublic(byte[] encoded) {
    if (encoded.length != ED25519_BYTES || !Ed25519.validatePublicKeyFull(encoded, 0)) {
      throw new PaserkException("A k4.seal public key must be a valid Ed25519 point");
    }
  }

  private static ECParameterSpec p384Parameters() {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec(P384));
      return parameters.getParameterSpec(ECParameterSpec.class);
    } catch (GeneralSecurityException e) {
      throw new PaserkException("P-384 is unavailable", e);
    }
  }

  private static void requireP384(ECParameterSpec parameters) {
    ECParameterSpec expected = p384Parameters();
    if (parameters == null
        || parameters.getCurve().getField().getFieldSize() != 384
        || !parameters.getOrder().equals(expected.getOrder())
        || !parameters.getGenerator().equals(expected.getGenerator())) {
      throw new PaserkException("Key must use the P-384 curve");
    }
  }

  private static void requireEd25519(String name) {
    if (!NamedParameterSpec.ED25519.getName().equalsIgnoreCase(name)) {
      throw new PaserkException("Key must use Ed25519");
    }
  }

  private static byte[] unsignedBigEndian(BigInteger number, int length) {
    byte[] encoded = number.toByteArray();
    int sourceOffset = encoded.length > 1 && encoded[0] == 0 ? 1 : 0;
    int sourceLength = encoded.length - sourceOffset;
    if (number.signum() < 0 || sourceLength > length) {
      throw new PaserkException("Integer does not fit the required key encoding");
    }
    byte[] result = new byte[length];
    System.arraycopy(encoded, sourceOffset, result, length - sourceLength, sourceLength);
    return result;
  }

  private static byte[] littleEndian(BigInteger number, int length) {
    byte[] bigEndian = unsignedBigEndian(number, length);
    reverse(bigEndian);
    return bigEndian;
  }

  private static BigInteger unsignedLittleEndian(byte[] encoded) {
    byte[] bigEndian = encoded.clone();
    reverse(bigEndian);
    return new BigInteger(1, bigEndian);
  }

  private static void reverse(byte[] bytes) {
    for (int left = 0, right = bytes.length - 1; left < right; left++, right--) {
      byte value = bytes[left];
      bytes[left] = bytes[right];
      bytes[right] = value;
    }
  }
}
