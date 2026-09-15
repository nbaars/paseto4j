/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations;

import org.paseto4j.commons.Version;
import org.paseto4j.paserk.operations.key.SealingPublicKey;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

/** Public-key encryption operation used by the PASERK seal type. */
public interface PKEInterface {

  Version version();

  String seal(byte[] localKey, SealingPublicKey publicKey);

  byte[] unseal(String paserk, SealingSecretKey secretKey);
}
