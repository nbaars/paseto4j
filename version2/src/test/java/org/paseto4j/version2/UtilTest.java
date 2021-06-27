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

package org.paseto4j.version2;

import org.junit.jupiter.api.Test;
import org.paseto4j.version2.Util;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

class UtilTest {

    @Test
    void pae() {
        assertAll(
                () -> assertEquals("0000000000000000", Util.pae(new String[]{})),
                () -> assertEquals("01000000000000000000000000000000", Util.pae("")),
                () -> assertEquals("020000000000000000000000000000000000000000000000", Util.pae("", "")),
                () -> assertEquals("0100000000000000070000000000000050617261676f6e", Util.pae("Paragon")),
                () -> assertEquals("0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665", Util.pae("Paragon", "Initiative")),
                () -> assertEquals("0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665", Util.pae("Paragon\n\0\0\0\0\0\0\0Initiative"))
        );
    }

}