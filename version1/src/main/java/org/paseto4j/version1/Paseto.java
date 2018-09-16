package org.paseto4j.version1;

public class Paseto {

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#encrypt
     */
    public static String encrypt(byte[] key, String payload, String footer) {
        return new PasetoLocal().encrypt(key, payload, footer);
    }

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt
     */
    public static String decrypt(byte[] key, String signedMessage, String footer) {
        return PasetoLocal.decrypt(key, signedMessage, footer);
    }

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign
     */
    public static String sign(byte[] privateKey, String payload, String footer) {
        //return PasetoPublic.sign(privateKey, payload, footer);
        return null;
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify
     */
    public static String parse(byte[] publicKey, String signedMessage, String footer) {
        //return PasetoPublic.verify(publicKey, signedMessage, footer);
        return null;
    }
}
