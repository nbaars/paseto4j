package org.paseto4j.version2;

import java.security.SignatureException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.sodium.Signature;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Version;

public class Version2 {

  public static void main(String... args) throws SignatureException {
    new Version2().signToken();
  }

  private void signToken() throws SignatureException {
    var seed = Bytes.random(32).toArray();
    var keyPair = Signature.KeyPair.fromSeed(Signature.Seed.fromBytes(seed));
    var publicKey = new PublicKey(keyPair.publicKey().bytesArray(), Version.V2);
    var privateKey = new PrivateKey(keyPair.secretKey().bytesArray(), Version.V2);

    String signedToken =
        Paseto.sign(
            privateKey,
            "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
            "Paragon Initiative Enterprises");
    System.out.println("Token is: " + signedToken);

    String token = Paseto.parse(publicKey, signedToken, "Paragon Initiative Enterprises");
    System.out.println("Token is: " + token);
  }
}
