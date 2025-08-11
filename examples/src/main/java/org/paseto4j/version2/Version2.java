/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import java.security.SignatureException;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import org.paseto4j.version1.CryptoFunctions;

public class Version2 {

  public static void main(String... args) throws SignatureException {
    new Version2().signToken();
  }

  private void signToken() throws SignatureException {
    var seed = CryptoFunctions.randomBytes();
    byte[] sk = new byte[64];
    byte[] pk = new byte[32];
    LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());
    lazySodium.cryptoSignSeedKeypair(pk, sk, seed);
    var publicKey = PublicKey.fromBytes(pk);
    var privateKey = PrivateKey.fromBytes(sk);

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
