/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

public class Conditions {

  private Conditions() {}

  public static void verify(boolean expression, String errorMessage) {
    if (!expression) {
      throw new PasetoException(errorMessage);
    }
  }

  public static boolean isNullOrEmpty(String str) {
    return str == null || str.isEmpty();
  }
}
