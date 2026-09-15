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
import org.paseto4j.paserk.keys.KeyEncoding;

/** PASERK public verification-key serialization. */
public final class PublicType implements PaserkType {

  private final Version version;

  public PublicType(Version version) {
    PaserkVersion.header(version);
    this.version = version;
  }

  @Override
  public byte[] decode(String paserk) {
    byte[] key = Util.decode(Util.payload(paserk, header()));
    validate(key);
    return key;
  }

  @Override
  public String encode(byte[] key) {
    validate(key);
    return header() + Util.encode(key);
  }

  @Override
  public String id(byte[] key) {
    return Pid.encode(version, encode(key));
  }

  @Override
  public String typeLabel() {
    return "public";
  }

  private String header() {
    return PaserkVersion.typeHeader(version, typeLabel());
  }

  private void validate(byte[] key) {
    switch (version) {
      case V3 -> KeyEncoding.decodeV3Public(key);
      case V4 -> KeyEncoding.decodeV4Public(key);
      default -> throw new PaserkException("Unsupported PASERK version");
    }
  }
}
