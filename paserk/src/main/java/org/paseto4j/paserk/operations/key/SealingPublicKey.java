/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.key;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Objects;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.keys.KeyEncoding;

/** A public key used exclusively for PASERK sealing. */
public final class SealingPublicKey {

  private final Version version;
  private final PublicKey key;

  private SealingPublicKey(Version version, PublicKey key) {
    this.version = version;
    this.key = Objects.requireNonNull(key, "key");
  }

  public static SealingPublicKey from(ECPublicKey key) {
    KeyEncoding.encodeV3Public(Objects.requireNonNull(key, "key"));
    return new SealingPublicKey(Version.V3, key);
  }

  public static SealingPublicKey from(EdECPublicKey key) {
    byte[] encoded = KeyEncoding.encodeV4Public(Objects.requireNonNull(key, "key"));
    KeyEncoding.validateV4SealingPublic(encoded);
    return new SealingPublicKey(Version.V4, key);
  }

  public static SealingPublicKey fromEncodedString(Version version, String encoded) {
    byte[] raw = Util.decode(encoded);
    return switch (version) {
      case V3 -> from(KeyEncoding.decodeV3Public(raw));
      case V4 -> from(KeyEncoding.decodeV4Public(raw));
      default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
    };
  }

  public Version version() {
    return version;
  }

  public PublicKey key() {
    return key;
  }

  public byte[] toBytes() {
    return switch (version) {
      case V3 -> KeyEncoding.encodeV3Public((ECPublicKey) key);
      case V4 -> KeyEncoding.encodeV4Public((EdECPublicKey) key);
      default -> throw new PaserkException("Unsupported PASERK version");
    };
  }

  public String toEncodedString() {
    return Util.encode(toBytes());
  }
}
