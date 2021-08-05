package org.paseto4j.commons;

import static org.paseto4j.commons.Conditions.verify;

public abstract class Key {

    public byte[] material;
    public Version version;

    public Key(byte[] keyMaterial, Version version) {
        this.material = keyMaterial;
        this.version = version;
    }

    public Key(byte[] keyMaterial, Version version, int size) {
        verify(keyMaterial.length == 32, "key should be " + size + " bytes");

        this.material = keyMaterial;
        this.version = version;
    }

    abstract public boolean isValidFor(Version v, Purpose p);

    public boolean hasLength(int length) {
        return length == material.length;
    }
}