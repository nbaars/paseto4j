/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PreAuthenticationEncoderTest {

  @Test
  void pae() {
    assertAll(
        () ->
            Assertions.assertEquals(
                "0000000000000000", HexToBytes.hexEncode(encode(new byte[][] {}))),
        () ->
            Assertions.assertEquals(
                "01000000000000000000000000000000",
                HexToBytes.hexEncode(encode("".getBytes(UTF_8)))),
        () ->
            Assertions.assertEquals(
                "020000000000000000000000000000000000000000000000",
                HexToBytes.hexEncode(encode("".getBytes(UTF_8), "".getBytes(UTF_8)))),
        () ->
            Assertions.assertEquals(
                "0100000000000000070000000000000050617261676f6e",
                HexToBytes.hexEncode(encode("Paragon".getBytes(UTF_8)))),
        () ->
            Assertions.assertEquals(
                "0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
                HexToBytes.hexEncode(
                    encode("Paragon".getBytes(UTF_8), "Initiative".getBytes(UTF_8)))),
        () ->
            Assertions.assertEquals(
                "0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665",
                HexToBytes.hexEncode(encode("Paragon\n\0\0\0\0\0\0\0Initiative".getBytes(UTF_8)))));
  }
}
