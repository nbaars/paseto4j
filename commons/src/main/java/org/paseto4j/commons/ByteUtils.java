package org.paseto4j.commons;

public class ByteUtils {

    private ByteUtils() {

    }

    public static byte[] concat(byte[]... arrays) {
        var length = 0;

        for (var i = 0; i < arrays.length; i++) {
            length = length + arrays[i].length;
        }

        var result = new byte[length];
        var end = 0;
        for (var i = 0; i < arrays.length; i++) {
            System.arraycopy(arrays[i], 0, result, end, arrays[i].length);
            end += arrays[i].length;
        }

        return result;
    }
}
