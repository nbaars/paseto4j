package org.paseto4j;

import com.google.common.base.Preconditions;

public class PasetoLocalBuilder {

    private byte[] key;
    private Purpose purpose;
    private String payload;
    private String footer;

    public PasetoLocalBuilder withKey(byte[] key) {
        this.key = key;
        return this;
    }

    public PasetoLocalBuilder payload(String payload) {
        this.payload = payload;
        return this;
    }

    public PasetoLocalBuilder footer(String footer) {
        this.footer = footer;
        return this;
    }

    public String createToken() {
        Preconditions.checkNotNull(this.key, "Key cannot be null");
        Preconditions.checkNotNull(this.payload, "Payload for the token cannot be null");

        return Paseto.encrypt(key, payload, footer);
    }

    public String decode() {
        Preconditions.checkNotNull(this.key, "Key cannot be null");
        Preconditions.checkNotNull(this.payload, "Payload for the token cannot be null");

        return Paseto.decrypt(key, payload, footer);
    }

}
