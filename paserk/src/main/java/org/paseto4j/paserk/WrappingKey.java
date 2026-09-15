/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import org.paseto4j.commons.Conditions;
import org.paseto4j.commons.Hex;

/** An immutable 256-bit key used exclusively to wrap and unwrap PASERK keys. */
public record WrappingKey(Hex key) {

  public WrappingKey {
    Conditions.verify(key != null, "Key must not be null");
    Conditions.verify(key.length() == 32, "Wrapping key must be 32 bytes in length");
  }

  public static WrappingKey fromBytes(byte[] keyBytes) {
    Conditions.verify(keyBytes != null, "Key must not be null");
    Conditions.verify(keyBytes.length == 32, "Wrapping key must be 32 bytes in length");
    return new WrappingKey(new Hex(keyBytes));
  }

  public static WrappingKey fromHexString(String key) {
    return new WrappingKey(Hex.fromString(key));
  }

  public byte[] toBytes() {
    return key.toBytes();
  }

  @Override
  public String toString() {
    return "****";
  }
}
