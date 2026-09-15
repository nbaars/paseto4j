/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.wrap;

import java.security.SecureRandom;
import java.util.Arrays;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.WrappingKey;
import org.paseto4j.paserk.operations.Crypto;

/** PASERK PIE version 3 implementation. */
public final class PieV3 extends PieVersion {

  public PieV3(WrappingKey wrappingKey) {
    this(wrappingKey, new SecureRandom());
  }

  public PieV3(WrappingKey wrappingKey, SecureRandom random) {
    super(Version.V3, wrappingKey, random);
  }

  @Override
  protected int encryptionMaterialLength() {
    return 48;
  }

  @Override
  protected int encryptionNonceLength() {
    return 16;
  }

  @Override
  protected int tagLength() {
    return 48;
  }

  @Override
  protected int secretKeyLength() {
    return 48;
  }

  @Override
  protected byte[] derive(int length, byte[] message, byte[] key) {
    return Arrays.copyOf(Crypto.hmacSha384(key, message), length);
  }

  @Override
  protected byte[] authenticate(byte[] message, byte[] key) {
    return Crypto.hmacSha384(key, message);
  }

  @Override
  protected byte[] crypt(byte[] input, byte[] key, byte[] nonce) {
    return Crypto.aes256Ctr(input, key, nonce);
  }
}
