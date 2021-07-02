/*
 * MIT License
 *
 * Copyright (c) 2018 Nanne Baars
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.paseto4j.version2;

import org.paseto4j.version1.Paseto;

import java.security.*;

public class Version1 {

    private static final String TOKEN = "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}";
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

        String signedToken = Paseto.sign(keyPair.getPrivate().getEncoded(), TOKEN, FOOTER);
        System.out.println("Signed token is: " + signedToken);

        String token = Paseto.parse(keyPair.getPublic().getEncoded(), signedToken, FOOTER);
        System.out.println("Signature is valid, token is: " + token);
    }

    private static void exampleV1PublicSignatureInvalid() throws SignatureException {
        KeyPair keyPair1 = generateKeyPair();
        KeyPair keyPair2 = generateKeyPair();

        String signedToken = Paseto.sign(keyPair1.getPrivate().getEncoded(), TOKEN, FOOTER);
        System.out.println("Signed token is: " + signedToken);

        String token = Paseto.parse(keyPair2.getPublic().getEncoded(), signedToken, FOOTER);
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
        String encryptedToken = Paseto.encrypt(secretKey, TOKEN, FOOTER);
        System.out.println("Encrypted token is: " + encryptedToken);

        String decryptedToken = Paseto.decrypt(secretKey, encryptedToken, FOOTER);
        System.out.println("Decrypted token is: " + decryptedToken);
    }

}
