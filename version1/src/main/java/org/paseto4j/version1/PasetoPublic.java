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

import org.paseto4j.commons.*;

import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

class PasetoPublic {

    private static final String PUBLIC = "v1.public.";

    private PasetoPublic() {
    }

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign
     */
    static String sign(PrivateKey privateKey, String payload, String footer) {
        requireNonNull(privateKey);
        requireNonNull(payload);
        verify(privateKey.isValidFor(Version.V1, Purpose.PURPOSE_PUBLIC), "Key is not valid for purpose and version");

        //2
        byte[] m2 = PreAuthenticationEncoder.encode(PUBLIC.getBytes(UTF_8), payload.getBytes(UTF_8), footer.getBytes(UTF_8));

        //3
        byte[] signature = CryptoFunctions.signRsaPssSha384(privateKey.material, m2);

        //4
        String signedToken = PUBLIC + getUrlEncoder().withoutPadding().encodeToString(ByteUtils.concat(payload.getBytes(UTF_8), signature));

        if (!isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify
     */
    static String parse(PublicKey publicKey, String signedMessage, String footer) throws SignatureException {
        requireNonNull(publicKey);
        requireNonNull(signedMessage);
        verify(publicKey.isValidFor(Version.V1, Purpose.PURPOSE_PUBLIC), "Key is not valid for purpose and version");

        String[] tokenParts = signedMessage.split("\\.");

        //1
        if (!isNullOrEmpty(footer)) {
            verify(MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        verify(signedMessage.startsWith(PUBLIC), "Token should start with " + PUBLIC);

        //3
        byte[] sm = getUrlDecoder().decode(tokenParts[2]);
        byte[] signature = Arrays.copyOfRange(sm, sm.length - 256, sm.length);
        byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 256);

        //4
        byte[] m2 = PreAuthenticationEncoder.encode(PUBLIC.getBytes(UTF_8), message, footer.getBytes(UTF_8));

        //5
        verifySignature(publicKey, m2, signature);

        return new String(message, UTF_8);
    }

    private static void verifySignature(PublicKey key, byte[] m2, byte[] signature) throws SignatureException {
        if (!CryptoFunctions.verifyRsaPssSha384(key.material, m2, signature)) {
            throw new SignatureException("Invalid signature");
        }
    }

}
