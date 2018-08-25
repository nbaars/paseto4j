package org.paseto4j.version2;

import net.consensys.cava.crypto.sodium.CryptoCavaWrapper;
import org.paseto4j.Paseto;

import static net.consensys.cava.crypto.sodium.CryptoCavaWrapper.crypto_sign_ed25519_seed_keypair;

public class Version2 {

    public static void main(String... args) {
        new Version2().signToken();
    }

    private void signToken() {
        byte[] seed = CryptoCavaWrapper.randomBytes(32);
        byte[] privateKey = new byte[64];
        byte[] publicKey = new byte[32];
        crypto_sign_ed25519_seed_keypair(seed, publicKey, privateKey);

        String signedToken = Paseto.sign(
                privateKey,
                "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
                "Paragon Initiative Enterprises");
        System.out.println("Token is: " + signedToken);

        String token = Paseto.parse(publicKey, signedToken, "Paragon Initiative Enterprises");
        System.out.println("Token is: " + token);
    }
}
