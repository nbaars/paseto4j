/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

public class PrivateKey extends Key<java.security.PrivateKey> {

  public PrivateKey(byte[] keyMaterial, Version version) {
    super(keyMaterial, version);
    if (version.ordinal() >= Version.V3.ordinal())
      throw new IllegalArgumentException(
          "Version 3 and above no longer support reading a key from a byte[]");
  }

  public PrivateKey(java.security.PrivateKey privateKey, Version version) {
    super(privateKey, version);
  }

  public boolean isValidFor(Version v, Purpose p) {
    return v == this.getVersion() && p == Purpose.PURPOSE_PUBLIC;
  }
}
