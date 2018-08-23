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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Verify;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.io.BaseEncoding.base64Url;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

class PasetoPublic {

    private static final String PUBLIC = "v1.public.";

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign
     */
    static String sign(byte[] privateKey, String payload, String footer) {
        Preconditions.checkNotNull(privateKey);
        Preconditions.checkNotNull(payload);

        //2
        byte[] m2 = Util.pae(PUBLIC.getBytes(UTF_8), payload.getBytes(UTF_8), footer.getBytes(UTF_8));

        //3
        byte[] signature = CryptoFunctions.signRsaPssSha384(privateKey, m2);

        //4
        String signedToken = PUBLIC + getUrlEncoder().withoutPadding().encodeToString(Bytes.concat(payload.getBytes(UTF_8), signature));

        if (!Strings.isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify
     */
    static String parse(byte[] publicKey, String signedMessage, String footer) {
        Preconditions.checkNotNull(publicKey);
        Preconditions.checkNotNull(signedMessage);

        String[] tokenParts = signedMessage.split("\\.");

        //1
        if (!Strings.isNullOrEmpty(footer)) {
            Verify.verify(MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        Verify.verify(signedMessage.startsWith(PUBLIC), "Token should start with " + PUBLIC);

        //3
        byte[] sm = getUrlDecoder().decode(tokenParts[2]);
        byte[] signature = Arrays.copyOfRange(sm, sm.length - 256, sm.length);
        byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 256);

        //4
        byte[] m2 = Util.pae(PUBLIC.getBytes(UTF_8), message, footer.getBytes(UTF_8));

        //5
        verify(publicKey, m2, signature);

        return new String(message, UTF_8);
    }

    private static void verify(byte[] key, byte[] m2, byte[] signature) {
        if (!CryptoFunctions.verifyRsaPssSha384(key, m2, signature)) {
            throw new RuntimeException("Invalid signature");
        }
    }

}
