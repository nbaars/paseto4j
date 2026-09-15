/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.wrap;

import java.security.SecureRandom;
import java.util.Objects;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.PaserkVersion;
import org.paseto4j.paserk.WrappingKey;
import org.paseto4j.paserk.operations.WrapInterface;

/** Version dispatcher for PASERK's Platform-Independent Encryption wrapping protocol. */
public final class Pie implements WrapInterface {

  private final WrapInterface implementation;

  public Pie(Version version, WrappingKey wrappingKey) {
    this(version, wrappingKey, new SecureRandom());
  }

  public Pie(Version version, WrappingKey wrappingKey, SecureRandom random) {
    implementation =
        switch (PaserkVersion.header(Objects.requireNonNull(version, "version"))) {
          case V3 -> new PieV3(wrappingKey, random);
          case V4 -> new PieV4(wrappingKey, random);
          default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
        };
  }

  @Override
  public Version version() {
    return implementation.version();
  }

  @Override
  public String prefix() {
    return implementation.prefix();
  }

  @Override
  public String wrapLocal(byte[] key) {
    return implementation.wrapLocal(key);
  }

  @Override
  public byte[] unwrapLocal(String paserk) {
    return implementation.unwrapLocal(paserk);
  }

  @Override
  public String wrapSecret(byte[] key) {
    return implementation.wrapSecret(key);
  }

  @Override
  public byte[] unwrapSecret(String paserk) {
    return implementation.unwrapSecret(paserk);
  }
}
