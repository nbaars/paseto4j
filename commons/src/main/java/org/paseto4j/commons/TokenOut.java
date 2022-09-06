package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlEncoder;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Token.header;

import java.util.Base64;

public class TokenOut {

  private final Token token;

  public TokenOut(Version version, Purpose purpose, byte[] token, String footer) {
    var pasetoToken =
        header(version, purpose) + getUrlEncoder().withoutPadding().encodeToString(token);

    if (!isNullOrEmpty(footer)) {
      pasetoToken =
          pasetoToken
              + "."
              + Base64.getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
    }
    this.token = new Token(pasetoToken, version, purpose);
  }

  @Override
  public String toString() {
    return this.token.toString();
  }
}
