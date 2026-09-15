/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import org.paseto4j.commons.Version;

/** Calculates a PASERK identifier for a secret signing key or wrapped secret key. */
public final class Sid {

  private Sid() {}

  public static String encode(Version version, String paserk) {
    return Ids.encode(version, "sid", paserk);
  }
}
