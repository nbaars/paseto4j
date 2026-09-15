/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.wrap;

import java.security.SecureRandom;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.WrappingKey;
import org.paseto4j.paserk.operations.Crypto;

/** PASERK PIE version 4 implementation. */
public final class PieV4 extends PieVersion {

  public PieV4(WrappingKey wrappingKey) {
    this(wrappingKey, new SecureRandom());
  }

  public PieV4(WrappingKey wrappingKey, SecureRandom random) {
    super(Version.V4, wrappingKey, random);
  }

  @Override
  protected int encryptionMaterialLength() {
    return 56;
  }

  @Override
  protected int encryptionNonceLength() {
    return 24;
  }

  @Override
  protected int tagLength() {
    return 32;
  }

  @Override
  protected int secretKeyLength() {
    return 64;
  }

  @Override
  protected byte[] derive(int length, byte[] message, byte[] key) {
    return Crypto.blake2b(length, message, key);
  }

  @Override
  protected byte[] authenticate(byte[] message, byte[] key) {
    return Crypto.blake2b(32, message, key);
  }

  @Override
  protected byte[] crypt(byte[] input, byte[] key, byte[] nonce) {
    return Crypto.xChaCha20(input, key, nonce);
  }
}
