package org.paseto4j;


import net.i2p.crypto.eddsa.Utils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PasetoTest {


    @ParameterizedTest
    @MethodSource
    void sign(String payload, String footer, String expectedToken) {
        byte[] privateKey = Utils.hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");
        assertEquals(expectedToken, Paseto.sign(privateKey, payload, footer));
    }

    private static Stream<Arguments> sign() {
        return Stream.of(
                Arguments.of("", "", "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA"),
                Arguments.of("", "Cuon Alpinus", "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz"),
                Arguments.of("Frank Denis rocks", "", "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM"),
                Arguments.of("Frank Denis rockz", "", "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML"),
                Arguments.of("Frank Denis rocks", "Cuon Alpinus", "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz"),
                Arguments.of("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", "", "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI"),
                Arguments.of("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", "Paragon Initiative Enterprises", "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz")
        );
    }

    @ParameterizedTest
    @MethodSource("sign")
    public void verify(String payload, String footer, String signedMessage) {
        byte[] publicKey = Utils.hexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");


        assertEquals(payload, Paseto.parse(publicKey, signedMessage, footer));
    }


}