package org.paseto4j;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.security.*;

import static com.google.common.io.BaseEncoding.base64Url;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlEncoder;

public class Paseto {

    static {
        Security.addProvider(new EdDSASecurityProvider());
    }

    /**
     * Sign the token
     *
     * <pre>
     *  If f is:
     *    Empty: return "h || base64url(m || sig)"
     *    Non-empty: return "h || base64url(m || sig) || . || base64url(f)"
     *
     *    where || means "concatenate"
     *    Note: base64url() means Base64url from RFC 4648 without = padding.
     * </pre>
     *
     * @param privateKey
     * @param payload
     * @param footer
     * @return
     */
    public static String sign(byte[] privateKey, String payload, String footer) {
        Preconditions.checkNotNull(privateKey);
        Preconditions.checkNotNull(payload);
        Preconditions.checkArgument(privateKey.length == 32, "Private key should be 32 bytes");

        String header = "v2.public.";
        byte[] m2 = BaseEncoding.base16().lowerCase().decode(Util.pae(header, payload, footer));
        byte[] signature = sign(privateKey, m2);

        String signedToken = header + getUrlEncoder().withoutPadding().encodeToString(Bytes.concat(payload.getBytes(UTF_8), signature));

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
}
