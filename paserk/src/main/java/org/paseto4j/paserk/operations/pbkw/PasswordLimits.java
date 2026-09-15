/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pbkw;

import org.paseto4j.paserk.PaserkException;

/** Resource limits applied before processing attacker-controlled password-wrapped PASERKs. */
public record PasswordLimits(int maxIterations, long maxMemoryBytes, int maxParallelism) {

  public PasswordLimits {
    if (maxIterations <= 0 || maxMemoryBytes <= 0 || maxParallelism <= 0) {
      throw new PaserkException("Password limits must be positive");
    }
  }

  public static PasswordLimits defaults() {
    return new PasswordLimits(10_000_000, 1024L * 1024 * 1024, 16);
  }
}
