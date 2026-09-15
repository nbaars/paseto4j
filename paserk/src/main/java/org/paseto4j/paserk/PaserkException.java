/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import org.paseto4j.commons.PasetoException;

/** Thrown when a PASERK is malformed, uses the wrong type, or fails authentication. */
public class PaserkException extends PasetoException {

  public PaserkException(String errorMessage) {
    super(errorMessage);
  }

  public PaserkException(String errorMessage, Throwable cause) {
    super(errorMessage);
    initCause(cause);
  }
}
