package org.paseto4j.examples;

import static org.paseto4j.commons.Version.V3;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.version3.Paseto;

public class Version3 {

  private static final String TOKEN =
      "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}";
  private static final String FOOTER = "Paragon Initiative Enterprises";

  public static void main(String... args) throws SignatureException {
    exampleV3Local();
    exampleV3Public();

    try {
      exampleV3PublicSignatureInvalid();
    } catch (Exception e) {
      System.out.println("Token is not valid");
    }
  }

  private static void exampleV3Public() throws SignatureException {
    KeyPair keyPair = generateKeyPair();

    String signedToken = Paseto.sign(new PrivateKey(keyPair.getPrivate(), V3), TOKEN, FOOTER);
    System.out.println("Signed token is: " + signedToken);

    String token = Paseto.parse(new PublicKey(keyPair.getPublic(), V3), signedToken, FOOTER);
    System.out.println("Signature is valid, token is: " + token);
  }

  private static void exampleV3PublicSignatureInvalid() throws SignatureException {
    KeyPair keyPair1 = generateKeyPair();
    KeyPair keyPair2 = generateKeyPair();

    String signedToken = Paseto.sign(new PrivateKey(keyPair1.getPrivate(), V3), TOKEN, FOOTER);
    System.out.println("Signed token is: " + signedToken);

    String token = Paseto.parse(new PublicKey(keyPair2.getPublic(), V3), signedToken, FOOTER);
    System.out.println("Signature is valid, token is: " + token);
  }

  private static KeyPair generateKeyPair() {
    try {
      var generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
      var spec = new ECGenParameterSpec("secp384r1");
      generator.initialize(spec);
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void exampleV3Local() {
    byte[] secretKey = new byte[32];
    new SecureRandom().nextBytes(secretKey);

    SecretKey key = new SecretKey(secretKey, V3);
    String encryptedToken = Paseto.encrypt(key, TOKEN, FOOTER);
    System.out.println("Encrypted token is: " + encryptedToken);

    String decryptedToken = Paseto.decrypt(new SecretKey(secretKey, V3), encryptedToken, FOOTER);
    System.out.println("Decrypted token is: " + decryptedToken);
  }
}
