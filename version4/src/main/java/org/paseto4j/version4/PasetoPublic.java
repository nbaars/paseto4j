package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V4;

import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.*;

public class PasetoPublic {
  private PasetoPublic() {}

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
   */
  static String sign(
      PrivateKey privateKey, String payload, String footer, String implicitAssertion) {

    requireNonNull(privateKey);
    requireNonNull(payload);
    verify(privateKey.isValidFor(V4, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    TokenOut token = new TokenOut(V4, PURPOSE_PUBLIC);

    // 3
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            token.header(),
            payload.getBytes(UTF_8),
            footer.getBytes(UTF_8),
            implicitAssertion.getBytes(UTF_8));

    // 4
    byte[] signature = CryptoFunctions.sign(privateKey.getKey(), m2);

    return token.payload(concat(payload.getBytes(UTF_8), signature)).footer(footer).doFinal();
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
   */
  public static String parse(
      PublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    verify(publicKey.isValidFor(V4, PURPOSE_PUBLIC), "Key is not valid for purpose and version");

    // 1 and 2
    Token token = new Token(signedMessage, V4, PURPOSE_PUBLIC, footer);

    // 4
    byte[] sm = getUrlDecoder().decode(token.getPayload());
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

    // 5
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            token.header(), message, footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

    // 6
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(PublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verify(key.getKey(), m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }
}
