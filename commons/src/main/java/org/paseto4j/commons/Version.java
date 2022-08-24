package org.paseto4j.commons;

public enum Version {
  V1("v1"),
  V2("v2"),
  V3("v3");

  private final String name;

  Version(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return name;
  }
};
