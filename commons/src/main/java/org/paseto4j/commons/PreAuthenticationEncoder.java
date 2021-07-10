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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PreAuthenticationEncoder {

    private PreAuthenticationEncoder() {
    }

    private static byte[] toLE64(int n) {
        long unsigned = Integer.toUnsignedLong(n);
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(unsigned);
        return buffer.array();
    }

    /**
     * Authentication Padding
     * <p>
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
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