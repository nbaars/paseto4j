/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.util.Locale;

/** Wrapper class for the chosen Paseto version */
public class TokenAlgorithm {

  private final Version version;
  private final Purpose purpose;

  public TokenAlgorithm(Version version, Purpose purpose) {
    this.version = version;
    this.purpose = purpose;
  }

  /**
   * Return the header which is a concatenation of the version and the purpose
   *
   * @return the header in the format: {version}.{purpose}.
   */
  public String header() {
    return String.format(Locale.ROOT, "%s.%s.", version.toString(), purpose.toString());
  }
}
