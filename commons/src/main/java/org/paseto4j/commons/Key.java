package org.paseto4j.commons;

import static org.paseto4j.commons.Conditions.verify;

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
        verify(keyMaterial.length == 32, "key should be " + size + " bytes");

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