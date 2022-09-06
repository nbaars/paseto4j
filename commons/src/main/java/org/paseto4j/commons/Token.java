package org.paseto4j.commons;

import static org.paseto4j.commons.Conditions.verify;

public class Token {

  protected final Version version;
  protected final Purpose purpose;
  private final String token;

  public Token(String token, Version version, Purpose purpose) {
    this.token = token;
    this.version = version;
    this.purpose = purpose;

    verify(token.startsWith(header()), "Token should start with " + header());
  }

  public String header() {
    return String.format("%s.%s.", version.toString(), purpose.toString());
  }

  public static String header(Version version, Purpose purpose) {
    return String.format("%s.%s.", version.toString(), purpose.toString());
  }

  @Override
  public String toString() {
    return token;
  }
}
