/*
 * MIT License
 *
 * Copyright (c) 2018 Nanne Baars
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
