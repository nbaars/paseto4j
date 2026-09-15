/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import java.util.Objects;
import org.paseto4j.paserk.operations.PKE;
import org.paseto4j.paserk.operations.key.SealingPublicKey;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

/** PASERK seal type backed by a version-specific public-key encryption operation. */
public final class Seal {

  private final PKE pke;

  public Seal(PKE pke) {
    this.pke = Objects.requireNonNull(pke, "pke");
  }

  public String encode(byte[] localKey, SealingPublicKey publicKey) {
    return pke.seal(localKey, publicKey);
  }

  public byte[] decode(String paserk, SealingSecretKey secretKey) {
    return pke.unseal(paserk, secretKey);
  }

  public String id(byte[] localKey, SealingPublicKey publicKey) {
    return Lid.encode(pke.version(), encode(localKey, publicKey));
  }

  public String id(String paserk) {
    return Lid.encode(pke.version(), paserk);
  }
}
