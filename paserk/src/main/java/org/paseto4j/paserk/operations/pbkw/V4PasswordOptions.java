/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pbkw;

import org.paseto4j.paserk.PaserkException;

/** Argon2id work factors used by k4.local-pw and k4.secret-pw. */
public record V4PasswordOptions(long memoryBytes, int iterations, int parallelism) {

  public static final long DEFAULT_MEMORY_BYTES = 64L * 1024 * 1024;
  public static final int DEFAULT_ITERATIONS = 2;
  public static final int DEFAULT_PARALLELISM = 1;

  public V4PasswordOptions {
    if (memoryBytes <= 0 || memoryBytes % 1024 != 0 || memoryBytes / 1024 > Integer.MAX_VALUE) {
      throw new PaserkException("Argon2 memory must be a positive whole number of KiB");
    }
    if (iterations <= 0 || parallelism <= 0) {
      throw new PaserkException("Argon2 iterations and parallelism must be positive");
    }
    if (memoryBytes / 1024 < 8L * parallelism) {
      throw new PaserkException("Argon2 memory is too small for the requested parallelism");
    }
  }

  public static V4PasswordOptions defaults() {
    return new V4PasswordOptions(
        DEFAULT_MEMORY_BYTES, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
  }
}
