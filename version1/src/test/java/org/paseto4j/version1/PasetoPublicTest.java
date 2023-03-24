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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;
import static org.paseto4j.commons.Version.V1;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PrivateKey;
import org.paseto4j.commons.PublicKey;

class PasetoPublicTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  // Test vector in PEM format converted to Hex
  public static String PRIVATE_KEY =
      "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100c9a4e04ede77a61de9e461e0c2"
          + "8196c33e6145f597490034f0d08ec1ed0512000b5a8b3d1828cd14277bdb79c21f106d375a9def831287fb8df3c24f21"
          + "bc312a1783a78931a3860c379b6b3da1747bd1ba063d4dd361e76a7c452d6fa098b6e060efd26587d617f33cc8b05cbb"
          + "96353add19c430c35d2f702104ed044d277b761bc606490194d4e57ab24350f17736320b9945eb205a479510b426139d"
          + "7000a5546e508d9277a2f5136be5f5b481ba66792293719119c0c08323793241ff400810b874984e6fc1d8a13826dd57"
          + "a6a553284a0b5fb5c3f156e8759ca7f246d64282f033c889d67bf016eabfd605ce401b3678b979204eb17541286efc66"
          + "c73ca30203010001028201005db68cb0dadf8c8a767b37a9f77bb68f82dc3e6147301c327e80cef7fda9cf95c9b108e9"
          + "19e34c7c436562b911a8d23f8fec435e5ef22bd493426859d279ddf78bfa19d0bf0b1a6f6f208214a086bc4cda41b018"
          + "0d5780ef9255ac2a26df128ef13e43efffd3564a2b43b20347032635f72fd4683d437f9a831e00f170d21aa4144866ef"
          + "6192542118d5e63e70e5e62f789cc67b279540fffd24bdab7dd1c45db2e68896d5e76a711aa15bfecbd7260c6f11c551"
          + "cc5687c594c239f500086808e53317c641fb45ff3cf87ed67628abac70a8bd19283c2b43c483856feb3432de3bd82273"
          + "9ae5ec47ad45045b16fb19e3401db17db053e956154901e36023ba8102818100e73fc25ea0c57d9f0c5c23c039eba2f3"
          + "2e47343b6edf4691f87397b010e7448f21b97b06343d3815f99747b9e4821af4f1f1550e61383de29493cd746096fe20"
          + "0268f30ace674ebcda7eb210c3b9f289aa2a29fe888515acf5cb48ba3908286bab0d89e2f833a25ccfc3737923c14974"
          + "ba266fd164ad5f381fe22f88f232972102818100df39f0006dbd417e804c47c5a4654e728828ac70a7b5de2789a582ab"
          + "99dee6c14bf84c0b795735cc3f728f56b17037a52020d9c426729d4ee40e7ad0705913d1b8c7fe00bc264defed74fd97"
          + "55030ea0b56fbae6fd7e7014867fae635ad6b55984bd68fed2b1e6dbccdacc89d6af79bfb35dca01481085bea9b20a6d"
          + "ce96cf430281806c5197500feab1ff102110b5f7eb82367a94ebc87314aecfad1b281056ba9d8895f975c0e03354d426"
          + "475057a8cbb0a8cfb3856de8e81944cae7b8b32c934d91dccf20190db9a24e1fe27cb2119c461969d5ba39f9e4acd489"
          + "85a11969a1829d7c50292861ae7dfd0f6cb3e828715f6107d8fd438def0fcd10523885e33d03410281802ed7417d5589"
          + "b90c8a6f774009d71837004b48a3fb0d36a8a5418dc1e46fd98c061cfc180c46388bbb64969f626c61c0cc95181d08d4"
          + "541e11ccd808950a9c160de8296c8e0e9b9c14ffcf96c9c7f271d6a0b35f7521eaf2e3a63739b1fe0bdfd4f2c9ed6ed8"
          + "d5d09993f0079c7d05d72c142a274aafece0ad4b26d513dca17102818100d19c43c9ce6e2de6e3044ec8aae4096716c4"
          + "514c9e9c31bf4a56ef6ec79fdc2e68eb3851b7ac0a7c26a5c3137f31940eecd85c2b40ab6a4997ae071bac2c7645a68c"
          + "14c91299ba6fd89b381377a85576cd0d07cb22a5316c48b954a3f603a8eb5845ed41fd5c1e91e0745d96904eb886e001"
          + "6678e9d923f7f1ccf68bdd3f4232";
  private static final String PUBLIC_KEY =
      "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c9a4e04ede77a61de9e461e0c28196c33e61"
          + "45f597490034f0d08ec1ed0512000b5a8b3d1828cd14277bdb79c21f106d375a9def831287fb8df3c24f21bc312a1783"
          + "a78931a3860c379b6b3da1747bd1ba063d4dd361e76a7c452d6fa098b6e060efd26587d617f33cc8b05cbb96353add19"
          + "c430c35d2f702104ed044d277b761bc606490194d4e57ab24350f17736320b9945eb205a479510b426139d7000a5546e"
          + "508d9277a2f5136be5f5b481ba66792293719119c0c08323793241ff400810b874984e6fc1d8a13826dd57a6a553284a"
          + "0b5fb5c3f156e8759ca7f246d64282f033c889d67bf016eabfd605ce401b3678b979204eb17541286efc66c73ca30203"
          + "010001";

  @ParameterizedTest
  @MethodSource("testVectors")
  void encryptTestVectors(String privateKey, String publicKey, String payload, String footer)
      throws SignatureException {
    String signedToken = Paseto.sign(new PrivateKey(hexToBytes(privateKey), V1), payload, footer);
    assertEquals(
        payload, Paseto.parse(new PublicKey(hexToBytes(publicKey), V1), signedToken, footer));
  }

  private static Stream<Arguments> testVectors() {
    return Stream.of(
        Arguments.of(
            PRIVATE_KEY,
            PUBLIC_KEY,
            "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            ""),
        Arguments.of(
            PRIVATE_KEY,
            PUBLIC_KEY,
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}"));
  }

  @Test
  void keySizeShouldBe2048() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(1024);
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey privateKey = new PrivateKey(keyPair.getPrivate().getEncoded(), V1);

    assertThrows(PasetoException.class, () -> Paseto.sign(privateKey, "msg", ""));
  }
}
