package org.paseto4j;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UtilTest {

    @Test
    public void pae() {
        assertAll(
                () -> assertEquals("0000000000000000", Util.pae(new String[]{})),
                () -> assertEquals("01000000000000000000000000000000", Util.pae("")),
                () -> assertEquals("020000000000000000000000000000000000000000000000", Util.pae("", "")),
                () -> assertEquals("0100000000000000070000000000000050617261676f6e", Util.pae("Paragon")),
                () -> assertEquals("0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665", Util.pae("Paragon", "Initiative")),
                () -> assertEquals("0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665", Util.pae("Paragon\n\0\0\0\0\0\0\0Initiative"))
        );
    }

}