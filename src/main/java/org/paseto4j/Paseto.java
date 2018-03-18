package org.paseto4j;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Verify;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.*;
import java.util.Arrays;

import static com.google.common.io.BaseEncoding.base64Url;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

public class Paseto {

    static {
        Security.addProvider(new EdDSASecurityProvider());
    }

    public static final String HEADER = "v2.public.";

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#sign
     */
    public static String sign(byte[] privateKey, String payload, String footer) {
        Preconditions.checkNotNull(privateKey);
        Preconditions.checkNotNull(payload);
        Preconditions.checkArgument(privateKey.length == 32, "Private key should be 32 bytes");

        byte[] m2 = BaseEncoding.base16().lowerCase().decode(Util.pae(HEADER, payload, footer));
        byte[] signature = sign(privateKey, m2);

        String signedToken = HEADER + getUrlEncoder().withoutPadding().encodeToString(Bytes.concat(payload.getBytes(UTF_8), signature));

        if (!Strings.isNullOrEmpty(footer)) {
            signedToken = signedToken + "." + base64Url().encode(footer.getBytes(UTF_8));
        }
        return signedToken;
    }

    private static byte[] sign(byte[] key, byte[] message) {
        try {
            Signature sgr = Signature.getInstance("NONEwithEdDSA", "EdDSA");

            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
            EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(key, spec);
            EdDSAPrivateKey privateKey = new EdDSAPrivateKey(privateKeySpec);

            sgr.initSign(privateKey);
            sgr.update(message);
            return sgr.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            throw new RuntimeException("Unable to sign token", e);
        }
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#verify
     */
    public static String parse(byte[] publicKey, String signedMessage, String footer) {
        Preconditions.checkNotNull(publicKey);
        Preconditions.checkNotNull(signedMessage);
        Preconditions.checkArgument(publicKey.length == 32, "Private key should be 32 bytes");


        String[] tokenParts = signedMessage.split("\\.");

        //1
        if (!Strings.isNullOrEmpty(footer)) {
            Verify.verify(org.bouncycastle.util.Arrays.constantTimeAreEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)), "footer does not match");
        }

        //2
        Verify.verify(signedMessage.startsWith(HEADER), "Token should start with " + HEADER);

        //3
        byte[] sm = getUrlDecoder().decode(tokenParts[2]);
        byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
        byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

        //4
        byte[] m2 = Util.pae(HEADER.getBytes(UTF_8), message, footer.getBytes(UTF_8));

        //5
        verify(publicKey, m2, signature);

        return new String(message);
    }


    private static void verify(byte[] key, byte[] message, byte[] signature) {
        try {
            Signature sgr = Signature.getInstance("NONEwithEdDSA", "EdDSA");

            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
            EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(key, spec);
            EdDSAPublicKey publicKey = new EdDSAPublicKey(publicKeySpec);

            sgr.initVerify(publicKey);
            sgr.update(message);

            if (!sgr.verify(signature)) {
                throw new RuntimeException("Invalid signature");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            throw new RuntimeException("Unable to verify token", e);
        }
    }


}
