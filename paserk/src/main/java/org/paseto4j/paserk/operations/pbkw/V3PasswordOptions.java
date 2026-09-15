/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pbkw;

import org.paseto4j.paserk.PaserkException;

/** PBKDF2 work factor used by k3.local-pw and k3.secret-pw. */
public record V3PasswordOptions(int iterations) {

  public static final int DEFAULT_ITERATIONS = 100_000;

  public V3PasswordOptions {
    if (iterations <= 0) {
      throw new PaserkException("PBKDF2 iterations must be positive");
    }
  }

  public static V3PasswordOptions defaults() {
    return new V3PasswordOptions(DEFAULT_ITERATIONS);
  }
}
