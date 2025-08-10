package org.paseto4j.version2;

public record PublicKey(byte[] key) {
  public PublicKey {
    if (key == null || key.length != 32) {
      throw new IllegalArgumentException("Key must be a byte array of length 32");
    }
  }
}
