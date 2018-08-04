package org.paseto4j;

import com.google.common.base.VerifyException;
import net.consensys.cava.crypto.sodium.CryptoCavaWrapper;
import net.i2p.crypto.eddsa.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasetoBuilderTest {

    @Test
    public void signToken() {
        byte[] privateKey = Utils.hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");

        String token = new PasetoBuilder()
                .publicPurpose()
                .withKey(privateKey)
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .build();
        assertEquals("v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz", token);
    }

    @Test
    public void verifyToken() {
        byte[] publicKey = Utils.hexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
        String token = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz";

        String parsedToken = new PasetoBuilder()
                .withKey(publicKey)
                .publicPurpose()
                .footer("Paragon Initiative Enterprises")
                .decode(token);
        assertEquals("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", parsedToken);
    }

    @Test
    public void encryptDecryptToken() {
        byte[] key = CryptoCavaWrapper.randomBytes(32);
        String encryptedToken = new PasetoBuilder()
                .withKey(key)
                .localPurpose()
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .build();
        String token = new PasetoBuilder()
                .withKey(key)
                .localPurpose()
                .footer("Paragon Initiative Enterprises")
                .decode(encryptedToken);

        assertEquals("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", token);
    }

    @Test
    public void encryptDecryptWrongFooter() {
        byte[] key = CryptoCavaWrapper.randomBytes(32);
        String encryptedToken = new PasetoBuilder()
                .withKey(key)
                .localPurpose()
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .build();

        assertThrows(VerifyException.class, () -> new PasetoBuilder()
                .withKey(key)
                .localPurpose()
                .footer("Incorrect footer")
                .decode(encryptedToken));
    }
}