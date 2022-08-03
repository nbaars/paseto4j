package org.paseto4j.commons;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class TestVectors {

    public static class TestVector {

        public String name;
        @JsonProperty("expect-fail")
        public boolean expectFail;
        public String key;
        public String nonce;
        public String token;
        public String payload;
        public String footer;
        @JsonProperty("implicit-assertion")
        public String implicitAssertion;
        @JsonProperty("public-key")
        private String publicKey;
        @JsonProperty("secret-key")
        private String secretKey;
        @JsonProperty("secret-key-pem")
        private String secretKeyPem;
        @JsonProperty("public-key-pem")
        private String publicKeyPem;

    }

    public String name;
    public List<TestVector> tests;

    private static final ObjectMapper mapper = new ObjectMapper();

    public static List<TestVector> v3(Purpose purpose) throws IOException {
        return read(Version.V3).tests.stream()
                .filter(vector -> purpose == Purpose.PURPOSE_LOCAL ? vector.key != null : vector.secretKeyPem != null)
                .collect(Collectors.toList());
    }

    private static TestVectors read(Version version) throws IOException {
        var is = TestVectors.class.getClassLoader().getResourceAsStream("test-vectors/" + version + ".json");
        return mapper.readValue(is, TestVectors.class);
    }
}
