package org.paseto4j.commons;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

import java.security.MessageDigest;
import java.util.Locale;

/** Representation of a Paseto token */
public class Token {

  private final String[] tokenParts;
  private final TokenAlgorithm tokenAlgorithm;
  private final String tokenString;

  Token(String tokenString, TokenAlgorithm tokenAlgorithm, String footer) {
    this.tokenString = tokenString;
    this.tokenParts = tokenString.split("\\.", -1);
    this.tokenAlgorithm = tokenAlgorithm;

    verify(
        tokenString.startsWith(tokenAlgorithm.header()),
        "Token should start with " + tokenAlgorithm.header());

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

  public Token(String tokenString, Version version, Purpose purpose, String footer) {
    this(tokenString, new TokenAlgorithm(version, purpose), footer);
  }

  private void validateTokenParts() {
    for (int i = 0; i < 3; i++) {
      verify(
          !isNullOrEmpty(tokenParts[i]),
          format(Locale.ROOT, "Token part %d cannot be null or empty", i));
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

  public byte[] header() {
    return tokenAlgorithm.header().getBytes(UTF_8);
  }

  @Override
  public String toString() {
    return tokenString;
  }
}
