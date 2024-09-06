package org.paseto4j.version4;

import java.security.SignatureException;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.SecretKey;

public class Paseto {

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt
   */
  public static String encrypt(SecretKey key, String payload, String footer) {
    return PasetoLocal.encrypt(key, payload, footer, "");
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt
   */
  public static String encrypt(
      SecretKey key, String payload, String footer, String implicitAssertion) {
    return PasetoLocal.encrypt(key, payload, footer, implicitAssertion);
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt
   */
  public static String decrypt(SecretKey key, String signedMessage, String footer) {
    return PasetoLocal.decrypt(key, signedMessage, footer);
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
   */
  public static String decrypt(
      SecretKey key, String signedMessage, String footer, String implicitAssertion) {
    return PasetoLocal.decrypt(key, signedMessage, footer, implicitAssertion);
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
   */
  public static String sign(PrivateKey privateKey, String payload) {
    return sign(privateKey, payload, "");
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
   */
  public static String sign(PrivateKey privateKey, String payload, String footer) {
    return sign(privateKey, payload, footer, "");
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
   */
  public static String sign(
      PrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    return PasetoPublic.sign(privateKey, payload, footer, implicitAssertion);
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
   */
  public static String parse(PublicKey publicKey, String signedMessage) throws SignatureException {
    return parse(publicKey, signedMessage, "");
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
   */
  public static String parse(PublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    return parse(publicKey, signedMessage, footer, "");
  }

  /**
   * https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
   */
  public static String parse(
      PublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    return PasetoPublic.parse(publicKey, signedMessage, footer, implicitAssertion);
  }
}
