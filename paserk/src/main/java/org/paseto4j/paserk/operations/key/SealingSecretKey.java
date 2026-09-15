/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.key;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.keys.KeyEncoding;

/** A secret key used exclusively for PASERK unsealing. */
public final class SealingSecretKey {

  private final Version version;
  private final PrivateKey key;

  private SealingSecretKey(Version version, PrivateKey key) {
    this.version = version;
    this.key = Objects.requireNonNull(key, "key");
  }

  public static SealingSecretKey from(ECPrivateKey key) {
    byte[] raw = KeyEncoding.encodeV3Secret(Objects.requireNonNull(key, "key"));
    try {
      return new SealingSecretKey(Version.V3, key);
    } finally {
      Util.wipe(raw);
    }
  }

  public static SealingSecretKey from(EdECPrivateKey key) {
    byte[] raw = KeyEncoding.encodeV4Secret(Objects.requireNonNull(key, "key"));
    try {
      return new SealingSecretKey(Version.V4, key);
    } finally {
      Util.wipe(raw);
    }
  }

  public static SealingSecretKey fromEncodedString(Version version, String encoded) {
    byte[] raw = Util.decode(encoded);
    try {
      return switch (version) {
        case V3 -> from(KeyEncoding.decodeV3Secret(raw));
        case V4 -> from(KeyEncoding.decodeV4Secret(raw));
        default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
      };
    } finally {
      Util.wipe(raw);
    }
  }

  public static SealingSecretKey generate(Version version) {
    try {
      return switch (version) {
        case V3 -> {
          KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
          generator.initialize(new ECGenParameterSpec("secp384r1"));
          yield from((ECPrivateKey) generator.generateKeyPair().getPrivate());
        }
        case V4 -> {
          KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
          generator.initialize(NamedParameterSpec.ED25519);
          yield from((EdECPrivateKey) generator.generateKeyPair().getPrivate());
        }
        default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
      };
    } catch (GeneralSecurityException e) {
      throw new PaserkException("Unable to generate a sealing key", e);
    }
  }

  public Version version() {
    return version;
  }

  public PrivateKey key() {
    return key;
  }

  public SealingPublicKey publicKey() {
    return switch (version) {
      case V3 -> SealingPublicKey.from(KeyEncoding.deriveV3Public((ECPrivateKey) key));
      case V4 -> SealingPublicKey.from(KeyEncoding.deriveV4Public((EdECPrivateKey) key));
      default -> throw new PaserkException("Unsupported PASERK version");
    };
  }

  public byte[] toBytes() {
    return switch (version) {
      case V3 -> KeyEncoding.encodeV3Secret((ECPrivateKey) key);
      case V4 -> KeyEncoding.encodeV4Secret((EdECPrivateKey) key);
      default -> throw new PaserkException("Unsupported PASERK version");
    };
  }

  public String toEncodedString() {
    byte[] raw = toBytes();
    try {
      return Util.encode(raw);
    } finally {
      Util.wipe(raw);
    }
  }
}
