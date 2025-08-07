/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;
import static org.paseto4j.commons.Version.V2;

import java.security.SecureRandom;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.SecretKey;

class PasetoLocalTest {

  @ParameterizedTest
  @MethodSource("encrypt")
  void encrypt(String key, String nonce, String payload, String footer, String expectedToken) {
    assertEquals(
        expectedToken,
        PasetoLocal.encrypt(
            new SecretKey(hexToBytes(key), V2), hexToBytes(nonce), payload, footer));
  }

  @ParameterizedTest
  @MethodSource("encrypt")
  void encryptAndDecryptShouldWork(
      String key, String nonce, String payload, String footer, String expectedToken) {
    String encryptedToken =
        PasetoLocal.encrypt(new SecretKey(hexToBytes(key), V2), hexToBytes(nonce), payload, footer);
    assertEquals(
        payload, Paseto.decrypt(new SecretKey(hexToBytes(key), V2), encryptedToken, footer));
  }

  private static Stream<Arguments> encrypt() {
    return Stream.of(
        Arguments.of(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "000000000000000000000000000000000000000000000000",
            "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "",
            "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w"),
        Arguments.of(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "000000000000000000000000000000000000000000000000",
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "",
            "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ"),
        Arguments.of(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "",
            "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA"),
        Arguments.of(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
            "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "",
            "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ"),
        Arguments.of(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
            "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"),
        Arguments.of(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
            "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
            "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"));
  }

  @Test
  void invalidTokenShouldGiveException() {
    var key =
        new SecretKey(
            hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"), V2);
    assertThrows(PasetoException.class, () -> PasetoLocal.decrypt(key, "v2.local.", ""));
  }

  @Test
  void encryptDecryptWrongFooter() {
    byte[] keyMaterial = new byte[32];
    new SecureRandom().nextBytes(keyMaterial);
    SecretKey key = new SecretKey(keyMaterial, V2);
    String encryptedToken =
        org.paseto4j.version2.Paseto.encrypt(
            key,
            "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
            "Paragon Initiative Enterprises");

    assertThrows(
        PasetoException.class, () -> Paseto.decrypt(key, encryptedToken, "Incorrect footer"));
  }

  @Test
  void shouldThrowErrorWhenTokenDoesNotStartWithLocal() {
    byte[] keyMaterial = new byte[32];
    new SecureRandom().nextBytes(keyMaterial);
    SecretKey key = new SecretKey(keyMaterial, V2);

    assertThrows(PasetoException.class, () -> PasetoLocal.decrypt(key, "test.sdfsfs.sdfsdf", ""));
  }
}
