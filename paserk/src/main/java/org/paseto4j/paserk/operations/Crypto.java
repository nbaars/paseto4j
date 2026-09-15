/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.version4.CryptoFunctions;

/** Shared cryptographic primitives for PASERK operations. */
public final class Crypto {

  private Crypto() {}

  public static byte[] sha384(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-384").digest(input);
    } catch (NoSuchAlgorithmException e) {
      throw new PaserkException("SHA-384 is unavailable", e);
    }
  }

  public static byte[] hmacSha384(byte[] key, byte[] message) {
    try {
      Mac mac = Mac.getInstance("HmacSHA384");
      mac.init(new SecretKeySpec(key, "HmacSHA384"));
      return mac.doFinal(message);
    } catch (GeneralSecurityException e) {
      throw new PaserkException("HMAC-SHA384 is unavailable", e);
    }
  }

  public static byte[] blake2b(int length, byte[] message) {
    return blake2b(length, message, null);
  }

  public static byte[] blake2b(int length, byte[] message, byte[] key) {
    Blake2bDigest digest =
        key == null
            ? new Blake2bDigest(length * 8)
            : new Blake2bDigest(key, length, null, null);
    digest.update(message, 0, message.length);
    byte[] output = new byte[length];
    digest.doFinal(output, 0);
    return output;
  }

  public static byte[] aes256Ctr(byte[] input, byte[] key, byte[] nonce) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(nonce));
      return cipher.doFinal(input);
    } catch (GeneralSecurityException e) {
      throw new PaserkException("AES-256-CTR is unavailable", e);
    }
  }

  public static byte[] xChaCha20(byte[] input, byte[] key, byte[] nonce) {
    return CryptoFunctions.xchacha20(input, nonce, key);
  }

  public static byte[] pbkdf2Sha384(
      byte[] password, byte[] salt, int iterations, int outputLength) {
    PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA384Digest());
    generator.init(password, salt, iterations);
    return ((KeyParameter) generator.generateDerivedParameters(outputLength * 8)).getKey();
  }

  public static byte[] argon2id(
      byte[] password,
      byte[] salt,
      int memoryKiB,
      int iterations,
      int parallelism,
      int outputLength) {
    Argon2Parameters parameters =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKiB)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .build();
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(parameters);
    byte[] output = new byte[outputLength];
    generator.generateBytes(password, output);
    return output;
  }
}
