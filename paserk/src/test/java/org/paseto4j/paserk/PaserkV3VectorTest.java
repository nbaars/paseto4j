/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

class PaserkV3VectorTest {

  private static final String LOCAL_KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String SECRET =
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";

  @Test
  void loadsSharedVectors() throws IOException {
    TestVectors.TestVector vector =
        TestVectors.paserk("test-vectors/k3.local.json").get(1);
    assertEquals(
        vector.paserk,
        org.paseto4j.paserk.version3.Paserk.encodeLocal(SecretKey.fromHexString(vector.key)));
  }

  @Test
  void serializesOfficialKeysAndIds() {
    SecretKey local = SecretKey.fromHexString(LOCAL_KEY);
    assertEquals(
        "k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8",
        org.paseto4j.paserk.version3.Paserk.encodeLocal(local));
    String publicPaserk =
        "k3.public.AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assertEquals(
        publicPaserk,
        org.paseto4j.paserk.version3.Paserk.encodePublicKey(
            org.paseto4j.paserk.version3.Paserk.decodePublicKey(publicPaserk)));
    ECPrivateKey secret = KeyEncoding.decodeV3Secret(bytes(SECRET));
    assertEquals(
        "k3.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        org.paseto4j.paserk.version3.Paserk.encodeSecretKey(secret));
    assertEquals(
        "k3.sid.DjlX1m4BBFtsnbwzw1zv_x0yRcrZpsvdr_gIxh_hg_Rv",
        org.paseto4j.paserk.version3.Paserk.secretKeyId(secret));
  }

  @Test
  void unwrapsPieAndPasswordVectors() {
    WrappingKey wrappingKey = WrappingKey.fromHexString(LOCAL_KEY);
    String pie =
        "k3.local-wrap.pie.cLJLT84tUuU-ZLPqKWfhlDw4c2Fhk896z97sK2eM2-HYB3dk_NrHsSS340sJPsBsb7VeFpDBQMzzqRXr4Oylrpzmg-NZC9FVqgaWm1gtEikm-1yvlGRYwstUFLvUF30NrBE3GxYzI63DqJPqfmHSmQ";
    assertEquals(SecretKey.fromBytes(new byte[32]), org.paseto4j.paserk.version3.Paserk.unwrapLocal(pie, wrappingKey));
    String password =
        "k3.local-pw.meWTPJohkeLsaKvlgigDksM935uSCUO3jvjEEHAK28QAAAPoNoLFUMJwo8QHOp5bJpbNzk-ZD_Q6jPtk0XhX4ctVhZnJ3ydru5AuXObwRudmG_RNK3PsJ7kpLSw15Vncc5vmGIkae4DKmBmPI1h3PmOxMGX_hj9DNfu1MIEEm9ukhKQq";
    assertEquals(
        SecretKey.fromHexString(LOCAL_KEY),
        org.paseto4j.paserk.version3.Paserk.unwrapLocalWithPassword(
            password, "636f727265637420686f727365206261747465727920737461706c65".toCharArray()));
  }

  @Test
  void unsealsAndWrapsOfficialKeys() {
    SealingSecretKey secret =
        SealingSecretKey.from(
            KeyEncoding.decodeV3Secret(
                bytes(
                    "2151be961a10011353138f4c7b13fe5a720c9aa76de487b854015a006af2b27e161c988de7d50ecb2691f135befdd87e")));
    String seal =
        "k3.seal.NsI9NFzAouTSs7V5mejAeyBLYcoeNlbb9eY8C2KnkPTsARsPLen9KfMFfgqeI50FAnuRCdcb4HmXPaY3i-ZdBXwfdqSiB_65lmIHosVOJ7chmqqscnBkA7vc3mEAXxM05hSytjBYFxwlUnfFE3Sq3YHUZrOELF7PM87K6FFOMqc6";
    assertEquals(
        SecretKey.fromBytes(new byte[32]),
        org.paseto4j.paserk.version3.Paserk.unseal(seal, secret));
    String wrapped = org.paseto4j.paserk.version3.Paserk.wrapSecret(secretKey(secret), WrappingKey.fromHexString(LOCAL_KEY));
    assertArrayEquals(
        KeyEncoding.encodeV3Secret(secretKey(secret)),
        KeyEncoding.encodeV3Secret(
            org.paseto4j.paserk.version3.Paserk.unwrapSecret(wrapped, WrappingKey.fromHexString(LOCAL_KEY))));
  }

  private static ECPrivateKey secretKey(SealingSecretKey key) {
    return (ECPrivateKey) key.key();
  }

  private static byte[] bytes(String hex) {
    return HexToBytes.hexToBytes(hex);
  }
}
