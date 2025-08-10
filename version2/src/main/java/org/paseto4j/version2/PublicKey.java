/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import org.paseto4j.PasetoException;

public record PublicKey(byte[] key) {
  public PublicKey {
    if (key == null || key.length != 32) {
      throw new PasetoException("Key must be a byte array of length 32");
    }
  }
}
