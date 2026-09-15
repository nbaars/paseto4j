/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.PaserkVersion;
import org.paseto4j.paserk.Util;

final class Ids {

  private Ids() {}

  static String encode(Version version, String type, String paserk) {
    if (paserk == null || paserk.isEmpty()) {
      throw new PaserkException("PASERK must not be empty");
    }
    String header = PaserkVersion.typeHeader(version, type);
    byte[] input = ByteUtils.concat(header.getBytes(US_ASCII), paserk.getBytes(US_ASCII));
    byte[] hash =
        switch (version) {
          case V3 -> sha384(input);
          case V4 -> blake2b264(input);
          default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
        };
    byte[] id = Arrays.copyOf(hash, 33);
    return header + Util.encode(id);
  }

  private static byte[] sha384(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-384").digest(input);
    } catch (NoSuchAlgorithmException e) {
      throw new PaserkException("SHA-384 is unavailable", e);
    }
  }

  private static byte[] blake2b264(byte[] input) {
    Blake2bDigest digest = new Blake2bDigest(264);
    digest.update(input, 0, input.length);
    byte[] output = new byte[33];
    digest.doFinal(output, 0);
    return output;
  }
}
