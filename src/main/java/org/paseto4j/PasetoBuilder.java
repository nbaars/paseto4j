package org.paseto4j;

import com.google.common.base.Preconditions;

public class PasetoBuilder {

    private byte[] key;
    private Purpose purpose;
    private String payload;
    private String footer;

    public PasetoBuilder withKey(byte[] key) {
        this.key = key;
        return this;
    }

    public PasetoBuilder localPurpose() {
        this.purpose = Purpose.LOCAL;
        return this;
    }

    public PasetoBuilder publicPurpose() {
        this.purpose = Purpose.PUBLIC;
        return this;
    }

    public PasetoBuilder payload(String payload) {
        this.payload = payload;
        return this;
    }

    public PasetoBuilder footer(String footer) {
        this.footer = footer;
        return this;
    }

    public String build() {
        Preconditions.checkNotNull(this.purpose, "Purpose must be set, either call localPurpose or publicPurpose");
        Preconditions.checkNotNull(this.key, "Key cannot be null");

        if (Purpose.LOCAL == this.purpose) {
            return Paseto.encrypt(key, payload, footer);
        } else {
            return Paseto.sign(key, payload, footer);
        }
    }

    public String decode(String token) {
        Preconditions.checkNotNull(this.purpose, "Purpose must be set, either call localPurpose or publicPurpose");
        Preconditions.checkNotNull(this.key, "Key cannot be null");

        if (Purpose.LOCAL == this.purpose) {
            return Paseto.decrypt(key, token, footer);
        } else {
            return Paseto.parse(key, token, footer);
        }
    }

}
