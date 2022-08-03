package org.paseto4j.commons;

public enum Purpose {
    PURPOSE_LOCAL("local"), PURPOSE_PUBLIC("public");

    private final String name;

    Purpose(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}

