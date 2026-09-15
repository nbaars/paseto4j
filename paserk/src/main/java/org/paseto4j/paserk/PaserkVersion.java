/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import org.paseto4j.commons.Version;

/** Version mapping shared by PASERK types and operations. */
public final class PaserkVersion {

  private PaserkVersion() {}

  public static String header(Version version) {
    return switch (version) {
      case V3 -> "k3";
      case V4 -> "k4";
      default -> throw new PaserkException("PASERK support is limited to versions 3 and 4");
    };
  }

  public static Version parse(String header) {
    return switch (header) {
      case "k3" -> Version.V3;
      case "k4" -> Version.V4;
      default -> throw new PaserkException("Invalid PASERK version");
    };
  }

  public static String typeHeader(Version version, String type) {
    return header(version) + "." + type + ".";
  }
}
