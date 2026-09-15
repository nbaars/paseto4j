/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import org.paseto4j.commons.Version;

/** Calculates a PASERK identifier for a public verification key. */
public final class Pid {

  private Pid() {}

  public static String encode(Version version, String paserk) {
    return Ids.encode(version, "pid", paserk);
  }
}
