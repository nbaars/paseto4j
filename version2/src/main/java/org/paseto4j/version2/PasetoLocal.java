package org.paseto4j.version2;

import com.google.common.base.Verify;
import net.consensys.cava.crypto.sodium.CryptoCavaWrapper;
import net.consensys.cava.crypto.sodium.XChaCha20Poly1305;

import java.util.Arrays;
import java.util.Base64;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.base.Verify.verify;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;
import static net.consensys.cava.bytes.Bytes.concatenate;
import static net.consensys.cava.bytes.Bytes.wrap;
import static net.consensys.cava.crypto.sodium.CryptoCavaWrapper.randomBytes;

class PasetoLocal {

    private static final String LOCAL = "v2.local.";

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
     */
    static String encrypt(byte[] key, String payload, String footer) {
        return encrypt(key, randomBytes(XChaCha20Poly1305.Nonce.length()), payload, footer);
    }

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
     */
    static String encrypt(byte[] key, byte[] randomKey, String payload, String footer) {
        checkNotNull(key);
        checkNotNull(payload);
        checkArgument(key.length == 32, "key should be 32 bytes");

        //3
        byte[] nonce = new byte[XChaCha20Poly1305.Nonce.length()];

        CryptoCavaWrapper.crypto_generichash_blake2b(
                nonce,
                payload.getBytes(UTF_8),
                randomKey);

        //4
        byte[] preAuth = Util.pae(LOCAL.toString().getBytes(UTF_8), nonce, footer.getBytes(UTF_8));

        //5
        byte[] cipherText = XChaCha20Poly1305.encrypt(
                payload.getBytes(UTF_8),
                preAuth,
                XChaCha20Poly1305.Key.fromBytes(key),
                XChaCha20Poly1305.Nonce.fromBytes(nonce));

        //6
        String signedToken = LOCAL + getUrlEncoder().withoutPadding().encodeToString(concatenate(wrap(nonce), wrap(cipherText)).toArray());

        if (!isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#decrypt
     */
    static String decrypt(byte[] key, String token, String footer) {
        checkNotNull(key);
        checkNotNull(token);
        checkArgument(key.length == 32, "Public key should be 32 bytes");

        String[] tokenParts = token.split("\\.");
        Verify.verify(tokenParts.length == 3 || tokenParts.length == 4, "Token should contain at least 3 parts");

        //1
        if (!isNullOrEmpty(footer)) {
            verify(Arrays.equals(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        verify(token.startsWith(LOCAL.toString()), "Token should start with " + LOCAL);

        //3
        byte[] ct = getUrlDecoder().decode(tokenParts[2]);
        byte[] nonce = Arrays.copyOfRange(ct, 0, XChaCha20Poly1305.Nonce.length());
        byte[] encrypedMessage = Arrays.copyOfRange(ct, XChaCha20Poly1305.Nonce.length(), ct.length);

        //4
        byte[] preAuth = Util.pae(LOCAL.toString().getBytes(UTF_8), nonce, footer.getBytes(UTF_8));

        //5
        byte[] message = XChaCha20Poly1305.decrypt(encrypedMessage, preAuth, XChaCha20Poly1305.Key.fromBytes(key), XChaCha20Poly1305.Nonce.fromBytes(nonce));
        return new String(message, UTF_8);
    }
}
