/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import java.util.Objects;
import org.paseto4j.paserk.operations.Wrap;

/** PASERK local-wrap type backed by a configured wrapping operation. */
public final class LocalWrap {

  private final Wrap wrap;

  public LocalWrap(Wrap wrap) {
    this.wrap = Objects.requireNonNull(wrap);
  }

  public byte[] decode(String paserk) {
    return wrap.localUnwrap(paserk);
  }

  public String encode(byte[] key) {
    return wrap.localWrap(key);
  }

  public String id(byte[] key) {
    return Lid.encode(wrap.version(), encode(key));
  }
}
