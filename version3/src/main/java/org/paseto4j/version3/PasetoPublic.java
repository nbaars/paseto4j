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

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.paseto4j.commons.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

class PasetoPublic {

    private static final String HEADER = String.format("%s.%s.", Version.V3, Purpose.PURPOSE_PUBLIC);

    private PasetoPublic() {
    }

    /**
     * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign
     */
    static String sign(PrivateKey privateKey, String payload, String footer, String implicitAssertion) {
        requireNonNull(privateKey);
        requireNonNull(payload);
        //1
        verify(privateKey.isValidFor(Version.V3, Purpose.PURPOSE_PUBLIC), "Key is not valid for purpose and version");

        //3
        byte[] pk = publicKey(privateKey);
        verify(pk.length == 49, "`pk` **MUST** be 49 bytes long");
        verify(pk[0] == (byte) 0x02 || pk[0] == (byte) 0x03, "The first byte **MUST** be `0x02` or `0x03`");
        byte[] m2 = PreAuthenticationEncoder.encode(pk, HEADER.getBytes(UTF_8), payload.getBytes(UTF_8), footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

        //4
        byte[] signature = CryptoFunctions.sign(privateKey.key, m2);
        verify(signature.length == 96, "The length of the signature **MUST** be 96 bytes long");

        //5
        String signedToken = HEADER + getUrlEncoder().withoutPadding().encodeToString(ByteUtils.concat(payload.getBytes(UTF_8), signature));
        if (!isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    /**
     * Parse the token, https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify
     */
    static String parse(PublicKey publicKey, String signedMessage, String footer, String implicitAssertion) throws SignatureException {
        requireNonNull(publicKey);
        requireNonNull(signedMessage);
        verify(publicKey.isValidFor(Version.V3, Purpose.PURPOSE_PUBLIC), "Key is not valid for purpose and version");

        String[] tokenParts = signedMessage.split("\\.");

        //1
        if (!isNullOrEmpty(footer)) {
            verify(MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        verify(signedMessage.startsWith(HEADER), "Token should start with " + HEADER);

        //3
        byte[] sm = getUrlDecoder().decode(tokenParts[2]);
        byte[] signature = Arrays.copyOfRange(sm, sm.length - 96, sm.length);
        byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 96);

        //4
        byte[] pk = toCompressed(publicKey);
        byte[] m2 = PreAuthenticationEncoder.encode(pk, HEADER.getBytes(UTF_8), message, footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

        //5
        verifySignature(publicKey, m2, signature);

        return new String(message, UTF_8);
    }

    private static void verifySignature(PublicKey key, byte[] m2, byte[] signature) throws SignatureException {
        if (!CryptoFunctions.verify(key.key, m2, signature)) {
            throw new SignatureException("Invalid signature");
        }
    }

    public static byte[] publicKey(PrivateKey key) {
        if (key.key instanceof ECPrivateKey) {
            return publicKeyFromPrivate(((ECPrivateKey) key.key).getS(), true);
        }
        throw new IllegalStateException("Only supported for EC");
    }

    /**
     * ECDSA Public Key Point Compression
     */
    private static byte[] publicKeyFromPrivate(BigInteger privKey, boolean compressed) {
        X9ECParameters params = SECNamedCurves.getByName("secp384r1");
        var curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        ECPoint point = curve.getG().multiply(privKey);
        return point.getEncoded(compressed);
    }

    private static byte[] toCompressed(PublicKey key) {
        if (key.key instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
            return ((org.bouncycastle.jce.interfaces.ECPublicKey)key.key).getQ().getEncoded(true);
        }
        throw new IllegalStateException("Public key is not an EC public key ");
    }


}
