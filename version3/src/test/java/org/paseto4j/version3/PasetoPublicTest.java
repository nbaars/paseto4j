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

package org.paseto4j.version3;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.TestVectors;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.Version.V3;

class PasetoPublicTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair readEC(String pem) throws IOException {
        Reader rdr = new StringReader(pem);
        Object parsed = new PEMParser(rdr).readObject();
        return new JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair) parsed);
    }

    @ParameterizedTest
    @MethodSource("testVectors")
    void signTestVectors(String name, boolean expectFail, String privateKeyPem, String payload, String footer, String implicitAssertion, String expectedToken) throws IOException, SignatureException {
        var keyPair = readEC(privateKeyPem);
        var privateKey = new PrivateKey(keyPair.getPrivate(), V3);
        var publicKey = new PublicKey(keyPair.getPublic(), V3);
        if (expectFail) {
            assertThrows(Exception.class, () -> Paseto.sign(privateKey, payload, footer, implicitAssertion));
        } else {
            assertEquals(expectedToken, Paseto.sign(privateKey, payload, footer, implicitAssertion));
            assertEquals(payload, Paseto.parse(publicKey, expectedToken, footer, implicitAssertion));
        }
    }

    private static Stream<Arguments> testVectors() throws IOException {
        return TestVectors.v3(Purpose.PURPOSE_PUBLIC).stream()
                .map(test -> Arguments.of(
                                test.name,
                                test.expectFail,
                                test.secretKeyPem,
                                test.payload,
                                test.footer,
                                test.implicitAssertion,
                                test.token
                        )
                );
    }

    @Test
    void normalUsage() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {
        var generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        var spec = new ECGenParameterSpec("secp384r1");
        generator.initialize(spec);
        var expectedPayload = "test message";
        var keyPair = generator.generateKeyPair();
        var signedMessage = Paseto.sign(new PrivateKey(keyPair.getPrivate(), V3), expectedPayload);

        var payload = Paseto.parse(new org.paseto4j.commons.PublicKey(keyPair.getPublic(), V3), signedMessage);

        Assertions.assertEquals(expectedPayload, payload);

    }
}