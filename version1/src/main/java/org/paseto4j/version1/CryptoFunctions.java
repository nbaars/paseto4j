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

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.paseto4j.commons.Conditions;

public class CryptoFunctions {

  private CryptoFunctions() {}

  /**
   * Return random bytes generated by {@link SecureRandom}
   *
   * @return 32 bytes of random data
   */
  public static byte[] randomBytes() {
    byte[] random = new byte[32];
    new SecureRandom().nextBytes(random);
    return random;
  }

  /**
   * Generate a HMAC-384 using Bouncy Castle
   *
   * @param key the key for the hmac
   * @param message the message to calculate the digest over
   * @return hmac of the message
   */
  public static byte[] hmac384(byte[] key, byte[] message) {
    try {
      Mac mac = Mac.getInstance("HMac-SHA384", PROVIDER_NAME);
      SecretKey secretKey = new SecretKeySpec(key, "HMac-SHA384");

      mac.init(secretKey);
      mac.reset();
      return mac.doFinal(message);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Encrypt the message with AES CTR mode.
   *
   * @param key the key for the encryption
   * @param nonce the nonce to be used as IV
   * @param message the message to be encrypted
   * @return the encrypted message
   */
  public static byte[] encryptAesCtr(byte[] key, byte[] nonce, byte[] message) {
    return encryptDecrypt(true, key, nonce, message);
  }

  /**
   * Decrypt the message with AES CTR mode.
   *
   * @param key the key for the encryption
   * @param nonce the nonce to be used as IV
   * @param message the message to be encrypted
   * @return the encrypted message
   */
  public static byte[] decryptAesCtr(byte[] key, byte[] nonce, byte[] message) {
    return encryptDecrypt(false, key, nonce, message);
  }

  private static byte[] encryptDecrypt(
      boolean encryption, byte[] key, byte[] nonce, byte[] message) {
    try {
      Cipher aes = Cipher.getInstance("AES/CTR/NoPadding", PROVIDER_NAME);
      SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

      aes.init(
          encryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
          secretKeySpec,
          new IvParameterSpec(nonce));
      return aes.doFinal(message);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static byte[] hkdfSha384(byte[] key, byte[] salt, byte[] info) {
    Digest digest = new SHA384Digest();
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
    hkdf.init(new HKDFParameters(key, salt, info));

    byte[] out = randomBytes();
    hkdf.generateBytes(out, 0, out.length);
    return out;
  }

  public static byte[] signRsaPssSha384(byte[] privateKey, byte[] msg) {
    PSSSigner signer =
        new PSSSigner(
            new RSAEngine(),
            new SHA384Digest(),
            new SHA384Digest(),
            new SHA384Digest().getDigestSize());

    try {
      RSAPrivateCrtKeyParameters key =
          (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(privateKey);
      Conditions.verify(key.getModulus().bitLength() == 2048, "RSA 2048 should be used");

      signer.init(true, key);
      signer.update(msg, 0, msg.length);
      return signer.generateSignature();
    } catch (IOException | CryptoException e) {
      throw new IllegalStateException(e);
    }
  }

  public static boolean verifyRsaPssSha384(byte[] publicKey, byte[] msg, byte[] signature) {
    PSSSigner signer =
        new PSSSigner(
            new RSAEngine(),
            new SHA384Digest(),
            new SHA384Digest(),
            new SHA384Digest().getDigestSize());

    try {
      signer.init(false, PublicKeyFactory.createKey(publicKey));
      signer.update(msg, 0, msg.length);
      return signer.verifySignature(signature);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
