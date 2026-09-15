/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.paserk.keys.KeyEncoding;

class KeyEncodingTest {

  private static final String V3_SECRET =
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
  private static final String V3_PUBLIC =
      "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
  private static final String V4_SECRET =
      "0000000000000000000000000000000000000000000000000000000000000000"
          + "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
  private static final String V4_PUBLIC =
      "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

  @Test
  void roundTripsVersion3KeysAndDerivesMatchingPublicKey() {
    ECPrivateKey secret = KeyEncoding.decodeV3Secret(bytes(V3_SECRET));
    ECPublicKey publicKey = KeyEncoding.decodeV3Public(bytes(V3_PUBLIC));

    assertArrayEquals(bytes(V3_SECRET), KeyEncoding.encodeV3Secret(secret));
    assertArrayEquals(bytes(V3_PUBLIC), KeyEncoding.encodeV3Public(publicKey));
    byte[] derivedPublic = KeyEncoding.encodeV3Public(KeyEncoding.deriveV3Public(secret));
    assertArrayEquals(derivedPublic, KeyEncoding.encodeV3Public(KeyEncoding.decodeV3Public(derivedPublic)));
  }

  @Test
  void roundTripsVersion4KeysAndDerivesMatchingPublicKey() {
    EdECPrivateKey secret = KeyEncoding.decodeV4Secret(bytes(V4_SECRET));
    EdECPublicKey publicKey = KeyEncoding.decodeV4Public(bytes(V4_PUBLIC));

    assertArrayEquals(bytes(V4_SECRET), KeyEncoding.encodeV4Secret(secret));
    assertArrayEquals(bytes(V4_PUBLIC), KeyEncoding.encodeV4Public(publicKey));
    assertArrayEquals(bytes(V4_PUBLIC), KeyEncoding.encodeV4Public(KeyEncoding.deriveV4Public(secret)));
  }

  @Test
  void rejectsInvalidSecretAndPublicEncodings() {
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV3Secret(new byte[47]));
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV3Secret(new byte[48]));
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV3Public(new byte[48]));
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV4Public(new byte[31]));
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV4Secret(new byte[63]));

    byte[] mismatched = bytes(V4_SECRET);
    mismatched[63] ^= 1;
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV4Secret(mismatched));
  }

  @Test
  void rejectsOutOfRangeVersion3Scalars() {
    byte[] zero = new byte[48];
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV3Secret(zero));

    byte[] order =
        bytes(
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
    assertThrows(PaserkException.class, () -> KeyEncoding.decodeV3Secret(order));
  }

  private static byte[] bytes(String hex) {
    return HexToBytes.hexToBytes(hex);
  }
}
