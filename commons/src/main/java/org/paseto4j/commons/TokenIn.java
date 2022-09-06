package org.paseto4j.commons;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

import java.security.MessageDigest;

/** Representation of a Paseto token */
public class TokenIn {

  private final String[] tokenParts;

  public TokenIn(String token, Version version, Purpose purpose, String footer) {
    new Token(token, version, purpose);
    this.tokenParts = token.split("\\.", -1);

    if (isNullOrEmpty(footer)) {
      verify(
          tokenParts.length != 4,
          "An non-empty footer has been passed, so the token should consist of exactly 4 parts");
    } else {
      verify(tokenParts.length != 3, "Token should consists of exactly 3 parts");
    }

    validateTokenParts();
    verifyFooter(footer);
  }

  private void validateTokenParts() {
    for (int i = 0; i < 3; i++) {
      verify(!isNullOrEmpty(tokenParts[i]), format("Token part %d cannot be null or empty", i));
    }
  }

  public String getPayload() {
    return tokenParts[2];
  }

  private void verifyFooter(String footer) {
    if (!isNullOrEmpty(footer)) {
      verify(
          MessageDigest.isEqual(getUrlDecoder().decode(tokenParts[3]), footer.getBytes(UTF_8)),
          "footer does not match");
    }
  }
}
