package org.paseto4j.commons;

public class SecretKey extends Key<javax.crypto.SecretKey> {
  public SecretKey(byte[] keyMaterial, Version version) {
    super(keyMaterial, version, 32);
  }

  public boolean isValidFor(Version v, Purpose p) {
    return v == this.getVersion() && p == Purpose.PURPOSE_LOCAL;
  }
}
