package org.paseto4j;

import okio.Buffer;

public class Util {

    /**
     * Authentication Padding
     * <p>
     * https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
     *
     * @param pieces string[] of the pieces
     */
    public static String pae(String... pieces) {
        Buffer accumulator = new Buffer();
        accumulator.writeLongLe(pieces.length);

        for (String piece : pieces) {
            accumulator.writeLongLe(piece.length());
            accumulator.writeUtf8(piece);
        }
        return accumulator.snapshot().hex();
    }

}
