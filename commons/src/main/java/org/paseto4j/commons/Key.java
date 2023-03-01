package org.paseto4j.commons;

public abstract class Key<T> {

  public T key;
  public byte[] material;
  public Version version;

  @Deprecated
  public Key(byte[] keyMaterial, Version version) {
    this.material = keyMaterial;
    this.version = version;
  }

  @Deprecated
  protected Key(byte[] keyMaterial, Version version, int size) {
    this.material = keyMaterial;
    this.version = version;
  }

  public Key(T key, Version version) {
    this.key = key;
    this.version = version;
  }

  public abstract boolean isValidFor(Version v, Purpose p);

  public boolean hasLength(int length) {
    return length == material.length;
  }
}
