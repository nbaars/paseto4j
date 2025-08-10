/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.paseto4j.commons.Conditions.verify;

public abstract class Key<T> {

  private T key;
  private byte[] material;
  private final Version version;

  protected Key(byte[] keyMaterial, Version version) {
    this.material = keyMaterial;
    this.version = version;
  }

  protected Key(byte[] keyMaterial, Version version, int size) {
    verify(keyMaterial.length == 32, "key should be " + size + " bytes");

    this.material = keyMaterial;
    this.version = version;
  }

  protected Key(T key, Version version) {
    this.key = key;
    this.version = version;
  }

  public abstract boolean isValidFor(Version v, Purpose p);

  public boolean hasLength(int length) {
    return length == material.length;
  }

  public Version getVersion() {
    return version;
  }

  public T getKey() {
    return key;
  }

  public byte[] getMaterial() {
    return material;
  }
}
