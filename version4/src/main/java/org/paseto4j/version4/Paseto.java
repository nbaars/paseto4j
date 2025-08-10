/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.SecretKey;

public class Paseto {

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt">encrypt</a>
   */
  public static String encrypt(SecretKey key, String payload, String footer) {
    return PasetoLocal.encrypt(key, payload, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt">decrypt</a>
   */
  public static String encrypt(
      SecretKey key, String payload, String footer, String implicitAssertion) {
    return PasetoLocal.encrypt(key, payload, footer, implicitAssertion);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  public static String decrypt(SecretKey key, String signedMessage, String footer) {
    return PasetoLocal.decrypt(key, signedMessage, footer);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign">sign</a>
   */
  public static String decrypt(
      SecretKey key, String signedMessage, String footer, String implicitAssertion) {
    return PasetoLocal.decrypt(key, signedMessage, footer, implicitAssertion);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign">sign</a>
   */
  public static String sign(EdECPrivateKey privateKey, String payload) {
    return sign(privateKey, payload, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign">sign</a>
   */
  public static String sign(EdECPrivateKey privateKey, String payload, String footer) {
    return sign(privateKey, payload, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign">sign</a>
   */
  public static String sign(
      EdECPrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    return PasetoPublic.sign(privateKey, payload, footer, implicitAssertion);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify">verify</a>
   */
  public static String parse(EdECPublicKey publicKey, String signedMessage)
      throws SignatureException {
    return parse(publicKey, signedMessage, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify">verify</a>
   */
  public static String parse(EdECPublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    return parse(publicKey, signedMessage, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify">verify</a>
   */
  public static String parse(
      EdECPublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    return PasetoPublic.parse(publicKey, signedMessage, footer, implicitAssertion);
  }
}
