/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.version4;

import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.Util;
import org.paseto4j.paserk.WrappingKey;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.PKE;
import org.paseto4j.paserk.operations.Wrap;
import org.paseto4j.paserk.operations.key.SealingPublicKey;
import org.paseto4j.paserk.operations.key.SealingSecretKey;
import org.paseto4j.paserk.operations.pbkw.PBKWv4;
import org.paseto4j.paserk.operations.pbkw.PasswordLimits;
import org.paseto4j.paserk.operations.pbkw.Passwords;
import org.paseto4j.paserk.operations.pbkw.V4PasswordOptions;
import org.paseto4j.paserk.operations.wrap.Pie;
import org.paseto4j.paserk.types.Lid;
import org.paseto4j.paserk.types.Local;
import org.paseto4j.paserk.types.LocalWrap;
import org.paseto4j.paserk.types.Pid;
import org.paseto4j.paserk.types.PublicType;
import org.paseto4j.paserk.types.Seal;
import org.paseto4j.paserk.types.SecretType;
import org.paseto4j.paserk.types.SecretWrap;
import org.paseto4j.paserk.types.Sid;

/** Static high-level entry point for PASERK version 4. */
public final class Paserk {

  private static final Version VERSION = Version.V4;
  private static final Local LOCAL = new Local(VERSION);
  private static final PublicType PUBLIC = new PublicType(VERSION);
  private static final SecretType SECRET = new SecretType(VERSION);
  private static final Seal SEAL = new Seal(new PKE(VERSION));

  private Paserk() {}

  public static String encodeLocal(SecretKey key) {
    byte[] raw = key.toBytes();
    try {
      return LOCAL.encode(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static SecretKey decodeLocal(String paserk) {
    byte[] raw = LOCAL.decode(paserk);
    try {
      return SecretKey.fromBytes(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static String encodePublicKey(EdECPublicKey key) {
    return PUBLIC.encode(KeyEncoding.encodeV4Public(key));
  }

  public static EdECPublicKey decodePublicKey(String paserk) {
    return KeyEncoding.decodeV4Public(PUBLIC.decode(paserk));
  }

  public static String encodeSecretKey(EdECPrivateKey key) {
    byte[] raw = KeyEncoding.encodeV4Secret(key);
    try {
      return SECRET.encode(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static EdECPrivateKey decodeSecretKey(String paserk) {
    byte[] raw = SECRET.decode(paserk);
    try {
      return KeyEncoding.decodeV4Secret(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static String localId(SecretKey key) {
    return Lid.encode(VERSION, encodeLocal(key));
  }

  public static String localId(String paserk) {
    return Lid.encode(VERSION, paserk);
  }

  public static String publicKeyId(EdECPublicKey key) {
    return Pid.encode(VERSION, encodePublicKey(key));
  }

  public static String secretKeyId(EdECPrivateKey key) {
    return Sid.encode(VERSION, encodeSecretKey(key));
  }

  public static String secretKeyId(String paserk) {
    return Sid.encode(VERSION, paserk);
  }

  public static String wrapLocal(SecretKey key, WrappingKey wrappingKey) {
    byte[] raw = key.toBytes();
    try {
      return localWrap(wrappingKey).encode(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static SecretKey unwrapLocal(String paserk, WrappingKey wrappingKey) {
    byte[] raw = localWrap(wrappingKey).decode(paserk);
    try {
      return SecretKey.fromBytes(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static String wrapSecret(EdECPrivateKey key, WrappingKey wrappingKey) {
    byte[] raw = KeyEncoding.encodeV4Secret(key);
    try {
      return secretWrap(wrappingKey).encode(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static EdECPrivateKey unwrapSecret(String paserk, WrappingKey wrappingKey) {
    byte[] raw = secretWrap(wrappingKey).decode(paserk);
    try {
      return KeyEncoding.decodeV4Secret(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  public static String wrapLocalWithPassword(SecretKey key, char[] password) {
    return wrapLocalWithPassword(key, password, V4PasswordOptions.defaults());
  }

  public static String wrapLocalWithPassword(
      SecretKey key, char[] password, V4PasswordOptions options) {
    byte[] raw = key.toBytes();
    byte[] passwordBytes = Passwords.utf8(password);
    try {
      return new PBKWv4().wrapLocal(raw, passwordBytes, options);
    } finally {
      Util.wipe(raw, passwordBytes);
    }
  }

  public static SecretKey unwrapLocalWithPassword(String paserk, char[] password) {
    return unwrapLocalWithPassword(paserk, password, PasswordLimits.defaults());
  }

  public static SecretKey unwrapLocalWithPassword(
      String paserk, char[] password, PasswordLimits limits) {
    byte[] passwordBytes = Passwords.utf8(password);
    byte[] raw = null;
    try {
      raw = new PBKWv4().unwrapLocal(paserk, passwordBytes, limits);
      return SecretKey.fromBytes(raw);
    } finally {
      Util.wipe(raw, passwordBytes);
    }
  }

  public static String wrapSecretWithPassword(EdECPrivateKey key, char[] password) {
    return wrapSecretWithPassword(key, password, V4PasswordOptions.defaults());
  }

  public static String wrapSecretWithPassword(
      EdECPrivateKey key, char[] password, V4PasswordOptions options) {
    byte[] raw = KeyEncoding.encodeV4Secret(key);
    byte[] passwordBytes = Passwords.utf8(password);
    try {
      return new PBKWv4().wrapSecret(raw, passwordBytes, options);
    } finally {
      Util.wipe(raw, passwordBytes);
    }
  }

  public static EdECPrivateKey unwrapSecretWithPassword(String paserk, char[] password) {
    return unwrapSecretWithPassword(paserk, password, PasswordLimits.defaults());
  }

  public static EdECPrivateKey unwrapSecretWithPassword(
      String paserk, char[] password, PasswordLimits limits) {
    byte[] passwordBytes = Passwords.utf8(password);
    byte[] raw = null;
    try {
      raw = new PBKWv4().unwrapSecret(paserk, passwordBytes, limits);
      return KeyEncoding.decodeV4Secret(raw);
    } finally {
      Util.wipe(raw, passwordBytes);
    }
  }

  public static String seal(SecretKey key, SealingPublicKey publicKey) {
    byte[] raw = key.toBytes();
    try {
      return SEAL.encode(raw, publicKey);
    } finally {
      Util.wipe(raw);
    }
  }

  public static String sealId(String paserk) {
    return SEAL.id(paserk);
  }

  public static SecretKey unseal(String paserk, SealingSecretKey secretKey) {
    byte[] raw = SEAL.decode(paserk, secretKey);
    try {
      return SecretKey.fromBytes(raw);
    } finally {
      Util.wipe(raw);
    }
  }

  private static LocalWrap localWrap(WrappingKey wrappingKey) {
    return new LocalWrap(new Wrap(new Pie(VERSION, wrappingKey)));
  }

  private static SecretWrap secretWrap(WrappingKey wrappingKey) {
    return new SecretWrap(new Wrap(new Pie(VERSION, wrappingKey)));
  }
}
