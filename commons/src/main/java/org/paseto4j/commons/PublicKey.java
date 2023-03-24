package org.paseto4j.commons;

public class PublicKey extends Key<java.security.PublicKey> {

  public PublicKey(byte[] keyMaterial, Version version) {
    super(keyMaterial, version);
  }

  public PublicKey(java.security.PublicKey publicKey, Version version) {
    super(publicKey, version);
  }

  public boolean isValidFor(Version v, Purpose p) {
    return v == this.getVersion() && p == Purpose.PURPOSE_PUBLIC;
  }
}
