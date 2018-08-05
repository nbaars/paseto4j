package org.paseto4j;

import com.google.common.base.Preconditions;
import net.consensys.cava.crypto.sodium.CryptoCavaWrapper;

public class PasetoPublicBuilder {

    private byte[] key;
    private String payload;
    private String footer;
    private byte[] seed;


    public PasetoPublicBuilder withSeed(byte[] seed) {
        this.seed = seed;
        return this;
    }

    public PasetoPublicBuilder withKey(byte[] key) {
        this.key = key;
        return this;
    }

    public PasetoPublicBuilder payload(String payload) {
        this.payload = payload;
        return this;
    }

    public PasetoPublicBuilder footer(String footer) {
        this.footer = footer;
        return this;
    }

    public String createToken() {
        Preconditions.checkNotNull(this.payload, "Payload for the token cannot be null");
        Preconditions.checkArgument(!(this.key != null && this.seed != null), "Both seed and key are specified, only one can be present");
        Preconditions.checkArgument(!(this.key == null && this.seed == null), "At least the seed or the private key must be specified");

        //https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
        if (this.seed != null ) {
            byte[] publicKey = new byte[64];
            byte[] privateKey = new byte[64];
            CryptoCavaWrapper.crypto_sign_ed25519_seed_keypair(this.seed, publicKey, privateKey);
            this.key = privateKey;
        }

        return Paseto.sign(this.key, payload, footer);
    }

    public String decode() {
        Preconditions.checkNotNull(this.key, "Key cannot be null");
        Preconditions.checkNotNull(this.payload, "Payload for the token cannot be null");

        return Paseto.parse(key, payload, footer);
    }

}
