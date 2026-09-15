/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class TestVectors {

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class TestVector {

    public String name;

    @JsonProperty("expect-fail")
    public boolean expectFail;

    public String key;
    public String nonce;
    public String token;
    public String payload;
    public String footer;
    public String paserk;
    public String type;
    public String version;
    public String unwrapped;

    @JsonProperty("unsealed")
    public String unsealed;

    @JsonProperty("wrapping-key")
    public String wrappingKey;

    public String password;

    public String seed;

    @JsonProperty("sealing-secret-key")
    public String sealingSecretKey;

    @JsonProperty("sealing-public-key")
    public String sealingPublicKey;

    public Map<String, Object> options;

    @JsonProperty("implicit-assertion")
    public String implicitAssertion;

    @JsonProperty("public-key")
    public String publicKey;

    @JsonProperty("secret-key")
    public String secretKey;

    @JsonProperty("secret-key-seed")
    public String secretKeySeed;

    @JsonProperty("secret-key-pem")
    public String secretKeyPem;

    @JsonProperty("public-key-pem")
    public String publicKeyPem;
  }

  public String name;
  public List<TestVector> tests;

  private static final ObjectMapper mapper = new ObjectMapper();

  public static List<TestVector> v3(Purpose purpose) throws IOException {
    return read("test-vectors/" + Version.V3 + ".json").tests.stream()
        .filter(
            vector ->
                purpose == Purpose.PURPOSE_LOCAL ? vector.key != null : vector.secretKeyPem != null)
        .collect(Collectors.toList());
  }

  public static List<TestVector> v4(Purpose purpose) throws IOException {
    return read("test-vectors/" + Version.V4 + ".json").tests.stream()
        .filter(
            vector ->
                purpose == Purpose.PURPOSE_LOCAL ? vector.key != null : vector.secretKeyPem != null)
        .collect(Collectors.toList());
  }

  /** Reads a test-vector document from the test classpath. */
  public static TestVectors read(String resource) throws IOException {
    try (var is = TestVectors.class.getClassLoader().getResourceAsStream(resource)) {
      if (is == null) {
        throw new IOException("Test-vector resource not found: " + resource);
      }
      return mapper.readValue(is, TestVectors.class);
    }
  }

  /** Reads PASERK vectors from a resource such as {@code test-vectors/paserk.json}. */
  public static List<TestVector> paserk(String resource) throws IOException {
    return read(resource).tests;
  }

  /** Reads PASERK vectors filtered by type and version from a combined resource. */
  public static List<TestVector> paserk(String resource, String type, Version version)
      throws IOException {
    return read(resource).tests.stream()
        .filter(vector -> type.equals(vector.type) && version.toString().equals(vector.version))
        .collect(Collectors.toList());
  }
}
