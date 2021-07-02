package org.paseto4j.version2;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.sodium.Signature;

import java.security.SignatureException;

public class Version2 {

    public static void main(String... args) throws SignatureException {
        new Version2().signToken();
    }

    private void signToken() throws SignatureException {
        var seed = Bytes.random(32).toArray();
        var keyPair = Signature.KeyPair.fromSeed(Signature.Seed.fromBytes(seed));
        var publicKey = new byte[32];
        var privateKey = keyPair.secretKey().bytesArray();

        String signedToken = Paseto.sign(
                privateKey,
                "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
                "Paragon Initiative Enterprises");
        System.out.println("Token is: " + signedToken);

        String token = Paseto.parse(publicKey, signedToken, "Paragon Initiative Enterprises");
        System.out.println("Token is: " + token);
    }
}
