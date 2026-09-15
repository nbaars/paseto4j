/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations;

import org.paseto4j.commons.Version;

/** Pluggable PASERK symmetric key-wrapping protocol. */
public interface WrapInterface {

  Version version();

  String prefix();

  String wrapLocal(byte[] key);

  byte[] unwrapLocal(String paserk);

  String wrapSecret(byte[] key);

  byte[] unwrapSecret(String paserk);
}
