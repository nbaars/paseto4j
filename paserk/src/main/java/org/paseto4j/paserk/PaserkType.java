/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

/** Common contract for PASERK types that encode raw PASETO key material. */
public interface PaserkType {

  byte[] decode(String paserk);

  String encode(byte[] key);

  String id(byte[] key);

  String typeLabel();
}
