/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations;

import java.util.Objects;
import org.paseto4j.commons.Version;

/** High-level symmetric PASERK key-wrapping operation. */
public final class Wrap {

  private final WrapInterface protocol;

  public Wrap(WrapInterface protocol) {
    this.protocol = Objects.requireNonNull(protocol);
  }

  public Version version() {
    return protocol.version();
  }

  public String localWrap(byte[] key) {
    return protocol.wrapLocal(key);
  }

  public byte[] localUnwrap(String paserk) {
    return protocol.unwrapLocal(paserk);
  }

  public String secretWrap(byte[] key) {
    return protocol.wrapSecret(key);
  }

  public byte[] secretUnwrap(String paserk) {
    return protocol.unwrapSecret(paserk);
  }
}
