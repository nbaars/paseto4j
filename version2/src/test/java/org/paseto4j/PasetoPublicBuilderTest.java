package org.paseto4j;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PasetoPublicBuilderTest {

    @Test
    public void signTokenWithSeed() {
        byte[] seed = Util.hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");

        String token = new PasetoPublicBuilder()
                .withSeed(seed)
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .createToken();
        assertEquals("v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz", token);
    }

    @Test
    public void signTokenWithPrivateKey() {
        byte[] privateKey = Util.hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");

        String token = new PasetoPublicBuilder()
                .withSeed(privateKey)
                .footer("Paragon Initiative Enterprises")
                .payload("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}")
                .createToken();
        assertEquals("v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz", token);
    }


    @Test
    public void verifyToken() {
        byte[] publicKey = Util.hexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
        String token = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz";

        String parsedToken = new PasetoPublicBuilder()
                .withKey(publicKey)
                .footer("Paragon Initiative Enterprises")
                .payload(token)
                .decode();
        assertEquals("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", parsedToken);
    }

}