package org.paseto4j.version1;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class CryptoFunctions {

    /**
     * @return 32 bytes of random data
     */
    public static byte[] randomBytes() {
        byte[] random = new byte[32];
        try {
            SecureRandom.getInstance("SHA1PRNG").nextBytes(random);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return random;
    }

    /**
     * Generate a HMAC-384 using Bouncy Castle
     *
     * @param key     the key for the hmac
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
     * @param key     the key for the encryption
     * @param nonce   the nonce to be used as IV
     * @param message the message to be encrypted
     * @return the encrypted message
     */
    public static byte[] encryptAesCtr(byte[] key, byte[] nonce, byte[] message) {
        return encryptDecrypt(true, key, nonce, message);
    }

    /**
     * Decrypt the message with AES CTR mode.
     *
     * @param key     the key for the encryption
     * @param nonce   the nonce to be used as IV
     * @param message the message to be encrypted
     * @return the encrypted message
     */
    public static byte[] decryptAesCtr(byte[] key, byte[] nonce, byte[] message) {
        return encryptDecrypt(false, key, nonce, message);
    }

    private static byte[] encryptDecrypt(boolean encryption, byte[] key, byte[] nonce, byte[] message) {
        try {
            Cipher aes = Cipher.getInstance("AES/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

            aes.init(encryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(nonce));
            return aes.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Apply HKDF with SHA-384
     *
     * @param key  the key to be used
     * @param salt the salt
     * @param info info
     * @return
     */
    public static byte[] hkdfSha384(byte[] key, byte[] salt, byte[] info) {
        Digest digest = new SHA384Digest();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(new HKDFParameters(key, salt, info));

        byte[] out = new byte[32];
        hkdf.generateBytes(out, 0, out.length);
        return out;
    }

}
