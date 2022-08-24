package org.paseto4j.commons;

public class ByteUtils {

  private ByteUtils() {}

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

  public static Pair<byte[]> split(byte[] array, int length) {
    var splitLength = Math.min(array.length, length);
    var r1 = new byte[splitLength];
    var r2 = new byte[array.length - splitLength];
    System.arraycopy(array, 0, r1, 0, splitLength);
    System.arraycopy(array, splitLength, r2, 0, array.length - splitLength);

    return new Pair<>(r1, r2);
  }
}
