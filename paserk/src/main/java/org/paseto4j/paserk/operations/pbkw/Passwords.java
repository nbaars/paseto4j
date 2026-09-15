/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk.operations.pbkw;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.paseto4j.paserk.PaserkException;

/** Password conversion without creating an immutable intermediate String. */
public final class Passwords {

  private Passwords() {}

  public static byte[] utf8(char[] password) {
    if (password == null) {
      throw new PaserkException("Password must not be null");
    }
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] bytes = new byte[encoded.remaining()];
    encoded.get(bytes);
    if (encoded.hasArray()) {
      Arrays.fill(
          encoded.array(),
          encoded.arrayOffset(),
          encoded.arrayOffset() + encoded.capacity(),
          (byte) 0);
    }
    return bytes;
  }
}
