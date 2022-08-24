package org.paseto4j.commons;

import com.google.common.io.BaseEncoding;

public class HexToBytes {

  public static byte[] hexToBytes(String hex) {
    return BaseEncoding.base16().lowerCase().decode(hex);
  }

  public static String hexEncode(byte[] bytes) {
    return BaseEncoding.base16().lowerCase().encode(bytes);
  }
}
