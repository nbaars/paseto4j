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

package org.paseto4j.version1;

import com.google.common.base.VerifyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasetoLocalTest {

    @ParameterizedTest
    @MethodSource("testVectors")
    void encryptTestVectors(String key, String nonce, String payload, String footer, String expectedToken) {
        assertEquals(expectedToken, PasetoLocal.encrypt(Util.hexToBytes(key), Util.hexToBytes(nonce), payload, footer));
    }

    @ParameterizedTest
    @MethodSource("testVectors")
    void decryptTestVectors(String key, String nonce, String payload, String footer, String encryptedToken) {
        assertEquals(payload, Paseto.decrypt(Util.hexToBytes(key), encryptedToken, footer));
    }

    private static Stream<Arguments> testVectors() {
        return Stream.of(
                Arguments.of(
                        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                        "000000000000000000000000000000000000000000000000",
                        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                        "",
                        "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
                ),
                Arguments.of("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                        "000000000000000000000000000000000000000000000000",
                        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                        "",
                        "v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw"
                ),
                Arguments.of("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                        "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
                        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                        "",
                        "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg"
                ),
                Arguments.of("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                        "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
                        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                        "",
                        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec"
                ),
                Arguments.of("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                        "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
                        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
                        "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9"
                ),
                Arguments.of("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                        "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
                        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
                        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9"
                )
        );
    }

    @Test
    public void normalUsage() {
        byte[] key = Util.hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        String encryptedToken = PasetoLocal.encrypt(
                key,
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"
        );

        String token = PasetoLocal.decrypt(key, encryptedToken, "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");

        assertEquals("{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", token);
    }

    @Test
    public void wrongFooter() {
        byte[] key = Util.hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        String encryptedToken = PasetoLocal.encrypt(
                key,
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "Test case footer"
        );

        assertThrows(
                VerifyException.class, () -> Paseto.decrypt(key, encryptedToken, "Wrong footer"), "Wrong footer");
    }

    @Test
    public void keySizeShouldBe2048() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        assertThrows(VerifyException.class, () -> Paseto.sign(keyPair.getPrivate().getEncoded(), "msg", ""));
    }
}