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

package org.paseto4j.version3;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.*;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.version3.CryptoFunctions.*;

class PasetoLocal {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String HEADER = String.format("%s.%s.", Version.V3, Purpose.PURPOSE_LOCAL);

    private PasetoLocal() {
    }

    /**
     * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#encrypt
     */
    public static String encrypt(SecretKey key, String payload, String footer) {
        return encrypt(key, randomBytes(), payload, footer, "");
    }

    /**
     * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#encrypt
     */
    public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
        return encrypt(key, randomBytes(), payload, footer, implicit);
    }

    static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer, String implicit) {
        requireNonNull(key);
        requireNonNull(payload);
        verify(key.isValidFor(Version.V3, Purpose.PURPOSE_LOCAL), "Key is not valid for purpose and version");
        verify(key.hasLength(32), "Key should be 32 bytes");

        //3
        byte[] nonce = randomKey;

        //4
        byte[] tmp = encryptionKey(key, nonce);
        Pair<byte[]> split = ByteUtils.split(tmp, 32);
        byte[] ek = split.first;
        byte[] n2 = split.second;
        byte[] ak = authenticationKey(key, nonce);

        //5
        byte[] cipherText = encryptAesCtr(ek, n2, payload.getBytes(UTF_8));

        //6
        byte[] preAuth = PreAuthenticationEncoder.encode(HEADER.getBytes(UTF_8), nonce, cipherText, footer.getBytes(UTF_8), implicit.getBytes(UTF_8));

        //7
        byte[] t = hmac384(ak, preAuth);

        //8
        String signedToken = HEADER + getUrlEncoder().withoutPadding().encodeToString(ByteUtils.concat(nonce, cipherText, t));

        if (!isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
        return hkdfSha384(key.material, ByteUtils.concat("paseto-encryption-key".getBytes(UTF_8), nonce));
    }

    private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
        return hkdfSha384(key.material, ByteUtils.concat("paseto-auth-key-for-aead".getBytes(UTF_8), nonce));
    }

    /**
     * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt
     */
    public static String decrypt(SecretKey key, String token, String footer) {
        return decrypt(key, token, footer, "");
    }

    /**
     * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt
     */
    static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
        requireNonNull(key);
        requireNonNull(token);

        //1
        verify(key.isValidFor(Version.V3, Purpose.PURPOSE_LOCAL), "Key is not valid for purpose and version");

        String[] tokenParts = token.split("\\.");
        verify(tokenParts.length == 3 || tokenParts.length == 4, "Token should contain at least 3 parts");

        //2
        if (!isNullOrEmpty(footer)) {
            verify(MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //3
        verify(token.startsWith(HEADER), "Token should start with " + HEADER);

        //4
        byte[] ct = getUrlDecoder().decode(tokenParts[2]);
        byte[] nonce = Arrays.copyOfRange(ct, 0, 32);
        byte[] t = Arrays.copyOfRange(ct, ct.length - 48, ct.length);
        byte[] c = Arrays.copyOfRange(ct, 32, ct.length - 48);

        //5
        byte[] tmp = encryptionKey(key, nonce);
        Pair<byte[]> split = ByteUtils.split(tmp, 32);
        byte[] ek = split.first;
        byte[] n2 = split.second;
        byte[] ak = authenticationKey(key, nonce);

        //6
        byte[] preAuth = PreAuthenticationEncoder.encode(HEADER.getBytes(UTF_8), nonce, c, footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

        //7
        byte[] t2 = hmac384(ak, preAuth);

        //8
        if (!MessageDigest.isEqual(t, t2)) {
            throw new IllegalStateException("HMAC verification failed");
        }

        //9
        byte[] message = decryptAesCtr(ek, n2, c);
        return new String(message, UTF_8);
    }
}
