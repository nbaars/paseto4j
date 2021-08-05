package org.paseto4j.commons;

public class PublicKey extends Key {
    public PublicKey(byte[] keyMaterial, Version version) {
        super(keyMaterial, version);
    }

    public boolean isValidFor(Version v, Purpose p) {
        return v == this.version && p == Purpose.PURPOSE_PUBLIC;
    }
}