package org.paseto4j;

public enum Purpose {

    PUBLIC("v2.public."),
    LOCAL("v2.local.");

    private final String header;

    Purpose(String header) {
        this.header = header;
    }

    @Override
    public String toString() {
        return header;
    }
}
