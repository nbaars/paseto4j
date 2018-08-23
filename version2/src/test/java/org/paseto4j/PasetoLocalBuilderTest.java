package org.paseto4j;

import com.google.common.base.VerifyException;
import net.consensys.cava.crypto.sodium.CryptoCavaWrapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasetoLocalBuilderTest {

    @Test
    public void encryptDecryptToken() {
        byte[] key = CryptoCavaWrapper.randomBytes(32);
        String encryptedToken = new PasetoLocalBuilder()
                .withKey(key)
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .createToken();
        String token = new PasetoLocalBuilder()
                .withKey(key)
                .footer("Paragon Initiative Enterprises")
                .payload(encryptedToken)
                .decode();

        assertEquals("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", token);
    }

    @Test
    public void encryptDecryptWrongFooter() {
        byte[] key = CryptoCavaWrapper.randomBytes(32);
        String encryptedToken = new PasetoLocalBuilder()
                .withKey(key)
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .createToken();

        assertThrows(VerifyException.class, () -> new PasetoPublicBuilder()
                .withKey(key)
                .footer("Incorrect footer")
                .payload(encryptedToken)
                .decode());
    }

}