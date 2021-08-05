package org.paseto4j.commons;

public class PrivateKey extends Key {
    public PrivateKey(byte[] keyMaterial, Version version) {
        super(keyMaterial, version);
    }

    public boolean isValidFor(Version v, Purpose p) {
        return v == this.version && p == Purpose.PURPOSE_PUBLIC;
    }
}
