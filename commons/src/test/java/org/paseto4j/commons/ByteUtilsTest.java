/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ByteUtilsTest {

  @Test
  void concatTwo() {
    var b1 = new byte[] {'a', 'b'};
    var b2 = new byte[] {'c', 'd'};

    var result = ByteUtils.concat(b1, b2);

    Assertions.assertArrayEquals(new byte[] {'a', 'b', 'c', 'd'}, result);
  }

  @Test
  void concatThree() {
    var b1 = new byte[] {'a', 'b'};
    var b2 = new byte[] {'c', 'd'};
    var b3 = new byte[] {'e', 'f'};

    var result = ByteUtils.concat(b1, b2, b3);

    Assertions.assertArrayEquals(new byte[] {'a', 'b', 'c', 'd', 'e', 'f'}, result);
  }

  @Test
  void concatEmptyRight() {
    var b1 = new byte[] {'a', 'b'};
    var b2 = new byte[0];

    var result = ByteUtils.concat(b1, b2);

    Assertions.assertArrayEquals(new byte[] {'a', 'b'}, result);
  }

  @Test
  void concatEmptyLeft() {
    var b1 = new byte[] {'a', 'b'};
    var b2 = new byte[0];

    var result = ByteUtils.concat(b2, b1);

    Assertions.assertArrayEquals(new byte[] {'a', 'b'}, result);
  }

  @Test
  void concatBothEmpty() {
    var b1 = new byte[0];
    var b2 = new byte[0];

    var result = ByteUtils.concat(b2, b1);

    Assertions.assertArrayEquals(new byte[] {}, result);
  }

  @Test
  void splitEqual() {
    var b = new byte[] {'a', 'b'};

    var result = ByteUtils.split(b, 1);

    Assertions.assertArrayEquals(new byte[] {'a'}, result.getFirst());
    Assertions.assertArrayEquals(new byte[] {'b'}, result.getSecond());
  }

  @Test
  void splitEmpty() {
    var b = new byte[] {};

    var result = ByteUtils.split(b, 1);

    Assertions.assertEquals(0, result.getFirst().length);
    Assertions.assertEquals(0, result.getSecond().length);
  }
}
