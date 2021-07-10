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

package org.paseto4j.version2;

import org.apache.tuweni.crypto.sodium.Signature;
import org.paseto4j.commons.Conditions;
import org.paseto4j.commons.PreAuthenticationEncoder;

import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;

class PasetoPublic {

    private PasetoPublic() {
    }

    private static final String PUBLIC = "v2.public.";

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#sign
     */
    static String sign(byte[] privateKey, String payload, String footer) {
        requireNonNull(privateKey);
        requireNonNull(payload);
        Conditions.verify(privateKey.length == 64, "Private signing key should be 64 bytes");

        byte[] m2 = encode(PUBLIC.getBytes(UTF_8), payload.getBytes(UTF_8), footer.getBytes(UTF_8));
        byte[] signature = Signature.signDetached(m2, Signature.SecretKey.fromBytes(privateKey));

        String signedToken = PUBLIC + getUrlEncoder().withoutPadding().encodeToString(concat(payload.getBytes(UTF_8), signature));

        if (!isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#verify
     */
    static String parse(byte[] publicKey, String signedMessage, String footer) throws SignatureException {
        requireNonNull(publicKey);
        requireNonNull(signedMessage);
        Conditions.verify(publicKey.length == 32, "Public key should be 32 bytes");

        String[] tokenParts = signedMessage.split("\\.");

        //1
        if (!isNullOrEmpty(footer)) {
            Conditions.verify(MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        Conditions.verify(signedMessage.startsWith(PUBLIC), "Token should start with " + PUBLIC);

        //3
        byte[] sm = getUrlDecoder().decode(tokenParts[2]);
        byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
        byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

        //4
        byte[] m2 = PreAuthenticationEncoder.encode(PUBLIC.getBytes(UTF_8), message, footer.getBytes(UTF_8));

        //5
        verify(publicKey, m2, signature);

        return new String(message);
    }

    private static void verify(byte[] key, byte[] message, byte[] signature) throws SignatureException {
        boolean valid = Signature.verifyDetached(message, signature, Signature.PublicKey.fromBytes(key));
        if (!valid) {
            throw new SignatureException("Invalid signature");
        }
    }

}
