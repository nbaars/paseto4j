package org.paseto4j.commons;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

class SecretKeyTest {

    private static byte[] SECRET_KEY = HexToBytes.hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");

    private static Stream<Arguments> combinations() {
        return Stream.of(
                Arguments.of(SECRET_KEY, Version.V1, Purpose.PURPOSE_PUBLIC, false),
                Arguments.of(SECRET_KEY, Version.V1, Purpose.PURPOSE_LOCAL, true),
                Arguments.of(SECRET_KEY, Version.V2, Purpose.PURPOSE_PUBLIC, false),
                Arguments.of(SECRET_KEY, Version.V2, Purpose.PURPOSE_LOCAL, true));
    }

    @ParameterizedTest
    @MethodSource("combinations")
    void verifyCombinations(byte[] secretKey, Version version, Purpose purpose, boolean expectedResult) {
        var key = new SecretKey(secretKey, version);

        Assertions.assertEquals(expectedResult, key.isValidFor(version, purpose));
    }

}