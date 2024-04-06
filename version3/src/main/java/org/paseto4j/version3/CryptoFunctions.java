/*
 * MIT License
 *
 * Copyright (c) 2022 Nanne Baars
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

package org.paseto4j.version3;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.Pair;

public class CryptoFunctions {

  private CryptoFunctions() {}

  /** Returns `length` bytes of random data. */
  public static byte[] randomBytes(int length) {
    byte[] random = new byte[length];
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
      Mac mac = Mac.getInstance("HMac-SHA384", "BC");
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
      Cipher aes = Cipher.getInstance("AES/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
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

  /**
   * Apply HKDF with SHA-384
   *
   * @param key the key to be used
   * @param info info
   */
  public static byte[] hkdfSha384(byte[] key, byte[] info) {
    Digest digest = new SHA384Digest();
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
    hkdf.init(new HKDFParameters(key, null, info));

    byte[] out = randomBytes(48);
    hkdf.generateBytes(out, 0, out.length);
    return out;
  }

  private static byte[] toUnsignedByteArray(BigInteger n, int length) {
    byte[] bs = BigIntegers.asUnsignedByteArray(n);
    if (bs.length < length) {
      byte[] tmp = new byte[length];
      System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
      bs = tmp;
    }
    return bs;
  }

  public static byte[] sign(PrivateKey privateKey, byte[] msg) {
    try {
      Signature signature = Signature.getInstance("SHA384withECDDSA", "BC");
      signature.initSign(privateKey);
      signature.update(msg);
      var sig =
          signature
              .sign(); // https://crypto.stackexchange.com/questions/33095/shouldnt-a-signature-using-ecdsa-be-exactly-96-bytes-not-102-or-103

      ASN1Sequence seq = ASN1Sequence.getInstance(sig);
      ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
      ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);

      return ByteUtils.concat(
          toUnsignedByteArray(r.getValue(), 48), toUnsignedByteArray(s.getValue(), 48));

    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature) {
    try {
      Signature verifier = Signature.getInstance("SHA384withECDDSA", "BC");
      verifier.initVerify(publicKey);
      verifier.update(msg);

      // Convert the signature see `sign`
      Pair<byte[]> pair = ByteUtils.split(signature, 48);
      DERSequence seq =
          new DERSequence(
              new ASN1Integer[] {
                new ASN1Integer(new BigInteger(1, pair.getFirst())),
                new ASN1Integer(new BigInteger(1, pair.getSecond()))
              });

      return verifier.verify(seq.getEncoded());
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
