package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlEncoder;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;

import java.util.Base64;

public class TokenOut {

  private final TokenAlgorithm tokenAlgorithm;
  private String footer;
  private String tokenPayload;

  public TokenOut(Version version, Purpose purpose) {
    this.tokenAlgorithm = new TokenAlgorithm(version, purpose);
  }

  public TokenOut footer(String footer) {
    this.footer = footer;
    return this;
  }

  public TokenOut payload(byte[] tokenPayload) {
    this.tokenPayload = getUrlEncoder().withoutPadding().encodeToString(tokenPayload);
    return this;
  }

  public String doFinal() {
    var pasetoToken = tokenAlgorithm.header() + tokenPayload;

    if (!isNullOrEmpty(footer)) {
      pasetoToken =
          pasetoToken
              + "."
              + Base64.getUrlEncoder().withoutPadding().encodeToString(footer.getBytes(UTF_8));
    }
    return new Token(pasetoToken, tokenAlgorithm, footer).toString();
  }

  public byte[] header() {
    return tokenAlgorithm.header().getBytes(UTF_8);
  }
}
