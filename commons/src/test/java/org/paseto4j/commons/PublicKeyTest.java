package org.paseto4j.commons;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

class PublicKeyTest {

    private static final String PUBLIC_KEY =
            "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c9a4e04ede77a61de9e461e0c28196c33e61"
                    + "45f597490034f0d08ec1ed0512000b5a8b3d1828cd14277bdb79c21f106d375a9def831287fb8df3c24f21bc312a1783"
                    + "a78931a3860c379b6b3da1747bd1ba063d4dd361e76a7c452d6fa098b6e060efd26587d617f33cc8b05cbb96353add19"
                    + "c430c35d2f702104ed044d277b761bc606490194d4e57ab24350f17736320b9945eb205a479510b426139d7000a5546e"
                    + "508d9277a2f5136be5f5b481ba66792293719119c0c08323793241ff400810b874984e6fc1d8a13826dd57a6a553284a"
                    + "0b5fb5c3f156e8759ca7f246d64282f033c889d67bf016eabfd605ce401b3678b979204eb17541286efc66c73ca30203"
                    + "010001";

    private static Stream<Arguments> combinations() {
        return Stream.of(
                Arguments.of(PUBLIC_KEY, Version.V1, Purpose.PURPOSE_PUBLIC, true),
                Arguments.of(PUBLIC_KEY, Version.V1, Purpose.PURPOSE_LOCAL, false),
                Arguments.of(PUBLIC_KEY, Version.V2, Purpose.PURPOSE_PUBLIC, true),
                Arguments.of(PUBLIC_KEY, Version.V2, Purpose.PURPOSE_LOCAL, false));
    }

    @ParameterizedTest
    @MethodSource("combinations")
    void verifyCombinations(String publicKey, Version version, Purpose purpose, boolean expectedResult) {
        var key = new PublicKey(publicKey.getBytes(StandardCharsets.UTF_8), version);

        Assertions.assertEquals(expectedResult, key.isValidFor(version, purpose));
    }

}