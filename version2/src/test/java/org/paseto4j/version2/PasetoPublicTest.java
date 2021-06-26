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


import org.apache.tuweni.crypto.sodium.Signature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SignatureException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasetoPublicTest {

    @ParameterizedTest
    @MethodSource
    void sign(String payload, String footer, String expectedToken) {
        byte[] privateKey = Util.hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
        assertEquals(expectedToken, org.paseto4j.version2.Paseto.sign(privateKey, payload, footer));
    }

    private static Stream<Arguments> sign() {
        return Stream.of(
                Arguments.of("", "", "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA"),
                Arguments.of("", "Cuon Alpinus", "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz"),
                Arguments.of("Frank Denis rocks", "", "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM"),
                Arguments.of("Frank Denis rockz", "", "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML"),
                Arguments.of("Frank Denis rocks", "Cuon Alpinus", "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz"),
                Arguments.of("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", "", "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI"),
                Arguments.of("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", "Paragon Initiative Enterprises", "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz"),
                Arguments.of("", "", "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA"),
                Arguments.of("", "Cuon Alpinus", "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz"),
                Arguments.of("Frank Denis rocks", "", "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM"),
                Arguments.of("Frank Denis rockz", "", "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML"),
                Arguments.of("Frank Denis rocks", "Cuon Alpinus", "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz"),
                Arguments.of("Frank Denis rocks", "Cuon Alpinus", "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz")
                //Arguments.of("{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}", "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9")
        );
    }

    @ParameterizedTest
    @MethodSource("sign")
    public void verify(String payload, String footer, String signedMessage) throws SignatureException {
        byte[] publicKey = Util.hexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");

        assertEquals(payload, org.paseto4j.version2.Paseto.parse(publicKey, signedMessage, footer));
    }

    @Test
    public void invalidSignature() {
        byte[] publicKey = Util.hexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");

        assertThrows(SignatureException.class, () ->
                Paseto.parse(publicKey, "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0A.Q3VvbiBBbHBpbnVz", "Cuon Alpinus"));
    }

    @Test
    public void signTokenWithSeed() {
        byte[] seed = Util.hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");
        Signature.KeyPair keyPair = Signature.KeyPair.fromSeed(Signature.Seed.fromBytes(seed));
        byte[] privateKey = keyPair.secretKey().bytesArray();
        byte[] publicKey = keyPair.publicKey().bytesArray();
        String token = PasetoPublic.sign(
                privateKey,
                "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
                "Paragon Initiative Enterprises");
        assertEquals("v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz", token);
    }
}