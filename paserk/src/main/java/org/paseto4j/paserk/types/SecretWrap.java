/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import java.util.Objects;
import org.paseto4j.paserk.operations.Wrap;

/** PASERK secret-wrap type backed by a configured wrapping operation. */
public final class SecretWrap {

  private final Wrap wrap;

  public SecretWrap(Wrap wrap) {
    this.wrap = Objects.requireNonNull(wrap);
  }

  public byte[] decode(String paserk) {
    return wrap.secretUnwrap(paserk);
  }

  public String encode(byte[] key) {
    return wrap.secretWrap(key);
  }

  public String id(byte[] key) {
    return Sid.encode(wrap.version(), encode(key));
  }
}
