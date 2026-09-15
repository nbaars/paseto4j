/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.types;

import org.paseto4j.commons.Version;
import org.paseto4j.paserk.PaserkException;
import org.paseto4j.paserk.PaserkType;
import org.paseto4j.paserk.PaserkVersion;
import org.paseto4j.paserk.Util;

/** PASERK local-key serialization. */
public final class Local implements PaserkType {

  private final Version version;

  public Local(Version version) {
    PaserkVersion.header(version);
    this.version = version;
  }

  @Override
  public byte[] decode(String paserk) {
    byte[] key = Util.decode(Util.payload(paserk, header()));
    requireLength(key);
    return key;
  }

  @Override
  public String encode(byte[] key) {
    requireLength(key);
    return header() + Util.encode(key);
  }

  @Override
  public String id(byte[] key) {
    return Lid.encode(version, encode(key));
  }

  @Override
  public String typeLabel() {
    return "local";
  }

  private String header() {
    return PaserkVersion.typeHeader(version, typeLabel());
  }

  private static void requireLength(byte[] key) {
    if (key == null || key.length != 32) {
      throw new PaserkException("A local key must be exactly 32 bytes");
    }
  }
}
