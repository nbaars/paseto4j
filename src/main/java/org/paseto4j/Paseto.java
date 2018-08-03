package org.paseto4j;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import java.security.Security;

public class Paseto {

    static {
        Security.addProvider(new EdDSASecurityProvider());
    }

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
     */
    public static String encrypt(byte[] key, String payload, String footer) {
        return PasetoLocal.encrypt(key, payload, footer);
    }

    /**
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#decrypt
     */
    public static String decrypt(byte[] key, String signedMessage, String footer) {
        return PasetoLocal.decrypt(key, signedMessage, footer);
    }

    /**
     * Sign the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#sign
     */
    public static String sign(byte[] privateKey, String payload, String footer) {
        return PasetoPublic.sign(privateKey, payload, footer);
    }

    /**
     * Parse the token, https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#verify
     */
    public static String parse(byte[] publicKey, String signedMessage, String footer) {
        return PasetoPublic.parse(publicKey, signedMessage, footer);
    }
}
