/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.paseto4j.commons.Version.V1;

import java.security.*;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.version1.Paseto;

public class Version1 {

  private static final String TOKEN =
      "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}";
  private static final String FOOTER = "Paragon Initiative Enterprises";

  public static void main(String[] args) throws SignatureException {
    exampleV1Local();
    exampleV1Public();

    try {
      exampleV1PublicSignatureInvalid();
    } catch (Exception e) {
      System.out.println("Token is not valid");
    }
  }

  private static void exampleV1Public() throws SignatureException {
    KeyPair keyPair = generateKeyPair();

    String signedToken = Paseto.sign(new PrivateKey(keyPair.getPrivate(), V1), TOKEN, FOOTER);
    System.out.println("Signed token is: " + signedToken);

    String token = Paseto.parse(new PublicKey(keyPair.getPublic(), V1), signedToken, FOOTER);
    System.out.println("Signature is valid, token is: " + token);
  }

  private static void exampleV1PublicSignatureInvalid() throws SignatureException {
    KeyPair keyPair1 = generateKeyPair();
    KeyPair keyPair2 = generateKeyPair();

    String signedToken = Paseto.sign(new PrivateKey(keyPair1.getPrivate(), V1), TOKEN, FOOTER);
    System.out.println("Signed token is: " + signedToken);

    String token = Paseto.parse(new PublicKey(keyPair2.getPublic(), V1), signedToken, FOOTER);
    System.out.println("Signature is valid, token is: " + token);
  }

  private static KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static void exampleV1Local() {
    byte[] secretKey = SecureRandom.getSeed(32);
    String encryptedToken = Paseto.encrypt(new SecretKey(secretKey), TOKEN, FOOTER);
    System.out.println("Encrypted token is: " + encryptedToken);

    String decryptedToken = Paseto.decrypt(new SecretKey(secretKey), encryptedToken, FOOTER);
    System.out.println("Decrypted token is: " + decryptedToken);
  }
}
