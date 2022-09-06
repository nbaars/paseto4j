package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class TokenTest {

  private final String token =
      "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";

  @Test
  void tokenShouldConsistOfMinimalThreeParts() {
    assertThrows(PasetoException.class, () -> new TokenIn("v1.local.", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void emptyPartsShouldNotBeAllowed() {
    assertThrows(PasetoException.class, () -> new TokenIn("..", V1, PURPOSE_LOCAL, null));
    assertThrows(PasetoException.class, () -> new TokenIn("v1.\"\".", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void tokenHeaderShouldMatch() {
    assertDoesNotThrow(() -> new TokenIn("v1.local.dfksjlf", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void tokenDoesNotStartWithCorrectHeader() {
    assertThrows(
        PasetoException.class, () -> new TokenIn("v1.local.dfksjlf", V1, PURPOSE_PUBLIC, null));
  }

  @Test
  void noExpectedFooterPassed() {
    assertThrows(
        PasetoException.class, () -> new TokenIn("v1.local.dfksjlf.", V1, PURPOSE_LOCAL, null));
    assertThrows(
        PasetoException.class,
        () -> new TokenIn("v1.local.dfksjlf", V1, PURPOSE_LOCAL, "expectedFooter"));
  }

  @Test
  void expectedFooterPassedButNotInTheToken() {
    assertThrows(
        PasetoException.class, () -> new TokenIn("v1.local.dfksjlf.", V1, PURPOSE_LOCAL, "footer"));
  }

  @Test
  void expectedFooterEmptyOrNull() {
    assertThrows(
        PasetoException.class, () -> new TokenIn("v1.local.dfksjlf.", V1, PURPOSE_LOCAL, ""));
    assertThrows(
        PasetoException.class, () -> new TokenIn("v1.local.dfksjlf.", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void footerDoesNotMatch() {
    assertThrows(
        PasetoException.class, () -> new TokenIn(token, V1, PURPOSE_LOCAL, "wrong_footer"));
  }

  @Test
  void footerDoesMatch() {
    assertDoesNotThrow(
        () ->
            new TokenIn(
                token,
                V1,
                PURPOSE_LOCAL,
                "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"));
  }

  @Test
  void shouldReturnPayload() {
    TokenIn pasetoToken =
        new TokenIn(
            token, V1, PURPOSE_LOCAL, "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");

    Assertions.assertEquals(
        "IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc",
        pasetoToken.getPayload());
  }
}
