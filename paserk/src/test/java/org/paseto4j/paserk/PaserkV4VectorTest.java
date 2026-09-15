/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.interfaces.EdECPrivateKey;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

class PaserkV4VectorTest {

  private static final String LOCAL_KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String SECRET =
      "0000000000000000000000000000000000000000000000000000000000000000"
          + "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

  @Test
  void loadsSharedVectors() throws IOException {
    TestVectors.TestVector vector =
        TestVectors.paserk("test-vectors/k4.secret.json").get(1);
    assertEquals(
        vector.paserk,
        org.paseto4j.paserk.version4.Paserk.encodeSecretKey(
            KeyEncoding.decodeV4Secret(bytes(vector.key))));
  }

  @Test
  void serializesOfficialKeysAndIds() {
    SecretKey local = SecretKey.fromHexString(LOCAL_KEY);
    assertEquals(
        "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8",
        org.paseto4j.paserk.version4.Paserk.encodeLocal(local));
    String publicPaserk = "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assertEquals(
        publicPaserk,
        org.paseto4j.paserk.version4.Paserk.encodePublicKey(
            org.paseto4j.paserk.version4.Paserk.decodePublicKey(publicPaserk)));
    EdECPrivateKey secret = KeyEncoding.decodeV4Secret(bytes(SECRET));
    assertEquals(
        "k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ",
        org.paseto4j.paserk.version4.Paserk.encodeSecretKey(secret));
  }

  @Test
  void unwrapsPieAndPasswordVectors() {
    WrappingKey wrappingKey = WrappingKey.fromHexString(LOCAL_KEY);
    String pie =
        "k4.local-wrap.pie.y-PC8Zh6P1DoOBUdhRr7W8GWSgHtRKvE8PWWYA-qXy3fxJDmaRsxcZVQzuvXHZuBg5MqCgh_y5K0WbukJCrDX73Wdf631VBnE1DNHafbjnGNzFNWP59ba9ifsOAgE7Bw";
    assertEquals(SecretKey.fromBytes(new byte[32]), org.paseto4j.paserk.version4.Paserk.unwrapLocal(pie, wrappingKey));
    String password =
        "k4.local-pw.9VvzoqE_i23NOqsP9xoijQAAAAAEAAAAAAAAAgAAAAG_uxDZC-NsYyOW8OUOqISJqgHN8xIfAXiPfmFTfB4GPidUzm4aKzMGJmZtRPeyZCV11MxEJS3VMIRHXxYsfUQsmWLALpFwqUhxZdk_ymFcK2Nk0-N7CVp-";
    assertEquals(
        SecretKey.fromHexString(LOCAL_KEY),
        org.paseto4j.paserk.version4.Paserk.unwrapLocalWithPassword(
            password, "636f727265637420686f727365206261747465727920737461706c65".toCharArray()));
  }

  @Test
  void unsealsAndWrapsOfficialKeys() {
    SealingSecretKey secret =
        SealingSecretKey.from(
            KeyEncoding.decodeV4Secret(
                bytes(
                    "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1d"
                        + "b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023")));
    String seal =
        "k4.seal.OPFn-AEUsKUWtAUZrutVvd9YaZ4CmV4_lk6ii8N72l5gTnl8RlL_zRFqWTZZV9gSnPzARQ_QklrZ2Qs6cJGKOENNOnsDXL5haXcr-QbTXgoLVBvT4ruJ8MdjWXGRTVc9";
    assertEquals(
        SecretKey.fromBytes(new byte[32]),
        org.paseto4j.paserk.version4.Paserk.unseal(seal, secret));
    String wrapped =
        org.paseto4j.paserk.version4.Paserk.wrapSecret(
            (EdECPrivateKey) secret.key(), WrappingKey.fromHexString(LOCAL_KEY));
    assertArrayEquals(
        KeyEncoding.encodeV4Secret((EdECPrivateKey) secret.key()),
        KeyEncoding.encodeV4Secret(
            org.paseto4j.paserk.version4.Paserk.unwrapSecret(
                wrapped, WrappingKey.fromHexString(LOCAL_KEY))));
  }

  @Test
  void exposesSealId() {
    SealingSecretKey secret = SealingSecretKey.generate(Version.V4);
    String paserk =
        org.paseto4j.paserk.version4.Paserk.seal(
            SecretKey.fromHexString(LOCAL_KEY), secret.publicKey());
    assertEquals(
        org.paseto4j.paserk.types.Lid.encode(Version.V4, paserk),
        org.paseto4j.paserk.version4.Paserk.sealId(paserk));
  }

  private static byte[] bytes(String hex) {
    return HexToBytes.hexToBytes(hex);
  }
}
