/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PreAuthenticationEncoder {

  private PreAuthenticationEncoder() {}

  private static byte[] toLE64(int n) {
    long unsigned = Integer.toUnsignedLong(n);
    ByteBuffer buffer = ByteBuffer.allocate(8);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    buffer.putLong(unsigned);
    return buffer.array();
  }

  /**
   * Authentication Padding
   *
   * <p>https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
   *
   * @param pieces string[] of the pieces
   */
  public static byte[] encode(byte[]... pieces) {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
      bos.write(toLE64(pieces.length));

      for (byte[] piece : pieces) {
        bos.write(toLE64(piece.length));
        bos.write(piece);
      }
      return bos.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException("Unable to perform pre-authentication encoding");
    }
  }
}
