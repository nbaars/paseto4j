/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import org.paseto4j.commons.PasetoException;

public record PrivateKey(byte[] key) {
  public PrivateKey {
    if (key == null) {
      throw new PasetoException("Key must not be null");
    }
    if (key.length != 64) {
      throw new PasetoException("Key must be a byte array of length 64");
    }
  }
}
