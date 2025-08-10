/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.paseto4j.commons.SecretKey;

public class Paseto {

  private Paseto() {}

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#encrypt">encrypt</a>
   */
  public static String encrypt(SecretKey key, String payload, String footer) {
    return org.paseto4j.version1.PasetoLocal.encrypt(key, payload, footer);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt">decrypt</a>
   */
  public static String decrypt(SecretKey key, String signedMessage, String footer) {
    return PasetoLocal.decrypt(key, signedMessage, footer);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#sign">sign</a>
   */
  public static String sign(RSAPrivateKey privateKey, String payload, String footer) {
    return PasetoPublic.sign(privateKey, payload, footer);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md#verify">verify</a>
   */
  public static String parse(RSAPublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    return PasetoPublic.parse(publicKey, signedMessage, footer);
  }
}
