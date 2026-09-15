/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations;

import java.util.Objects;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.operations.key.SealingPublicKey;
import org.paseto4j.paserk.operations.key.SealingSecretKey;
import org.paseto4j.paserk.operations.pke.PKEv3;
import org.paseto4j.paserk.operations.pke.PKEv4;

/** Version dispatcher for PASERK public-key encryption. */
public final class PKE implements PKEInterface {

  private final PKEInterface implementation;

  public PKE(Version version) {
    implementation =
        switch (Objects.requireNonNull(version, "version")) {
          case V3 -> new PKEv3();
          case V4 -> new PKEv4();
          default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
        };
  }

  @Override
  public Version version() {
    return implementation.version();
  }

  @Override
  public String seal(byte[] localKey, SealingPublicKey publicKey) {
    return implementation.seal(localKey, publicKey);
  }

  @Override
  public byte[] unseal(String paserk, SealingSecretKey secretKey) {
    return implementation.unseal(paserk, secretKey);
  }
}
