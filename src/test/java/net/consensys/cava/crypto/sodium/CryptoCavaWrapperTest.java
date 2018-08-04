package net.consensys.cava.crypto.sodium;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoCavaWrapperTest {

    @Test
    public void randomBytes() {
        assertEquals(CryptoCavaWrapper.randomBytes(24).length, 24);
    }

    @Test
    public void emptyByteArray() {
        byte[] bytes = new byte[24];

        assertTrue(CryptoCavaWrapper.isEmpty(bytes));
    }

}