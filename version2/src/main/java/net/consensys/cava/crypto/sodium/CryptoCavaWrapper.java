/*
 * MIT License
 *
 * Copyright (c) 2018 Nanne Baars
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package net.consensys.cava.crypto.sodium;

import com.google.common.base.Verify;
import jnr.ffi.byref.LongLongByReference;

import java.util.function.IntSupplier;
import java.util.stream.IntStream;

/**
 * Class for exposing underlying generich hash for blake2b.
 * <p>
 * Necessary as by default {@link Sodium#crypto_generichash_blake2b} is defined as package-private
 */
public class CryptoCavaWrapper {

    public static final int VARIANT_URLSAFE_NO_PADDING = 7;

    private CryptoCavaWrapper() {
    }

    private interface SodiumDecoder {

        int call(byte[] in, byte[] out, LongLongByReference reference);

        default byte[] decode(byte[] in) {
            byte[] out = new byte[in.length];
            LongLongByReference reference = new LongLongByReference();
            runIt(() -> call(in, out, reference));
            byte[] result = new byte[reference.intValue()];
            System.arraycopy(out, 0, result, 0, reference.intValue());
            return result;
        }
    }

    public static byte[] base64Decode(byte[] base64Decoded) {
        return ((SodiumDecoder)
                (in, out, reference) ->
                        Sodium.sodium_base642bin(out, in.length, in, in.length, null, reference, null, VARIANT_URLSAFE_NO_PADDING)
        ).decode(base64Decoded);
    }

    public static byte[] hexToBin(byte[] hex) {
        return ((SodiumDecoder)
                (in, out, reference) -> Sodium.sodium_hex2bin(out, hex.length, hex, hex.length, null, reference, null)
        ).decode(hex);
    }

    public static void cryptoGenericHashBlake2b(byte[] out, byte[] in, byte[] key) {
        runIt(() -> Sodium.crypto_generichash_blake2b(out, out.length, in, in.length, key, key.length));
    }

    public static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        Sodium.randombytes(result, length);

        Verify.verify(!isEmpty(result), "Random generation failed, contains all zeroes");

        return result;
    }

    public static void cryptoSignDetached(byte[] out, byte[] msg, byte[] privateKey) {
        runIt(() -> Sodium.crypto_sign_detached(out, new LongLongByReference(), msg, msg.length, privateKey));
    }

    public static void cryptoSignEd25519SeedKeypair(byte[] seed, byte[] pkey, byte[] sk) {
        runIt(() -> Sodium.crypto_sign_ed25519_seed_keypair(pkey, sk, seed));
    }

    public static int cryptoSignVerifyDetached(byte[] signature, byte[] message, byte[] publicKey) {
        return Sodium.crypto_sign_verify_detached(signature, message, message.length, publicKey);
    }

    static boolean isEmpty(final byte[] data) {
        return IntStream.range(0, data.length).parallel().allMatch(i -> data[i] == 0);
    }

    private static void runIt(IntSupplier s) {
        int returnCode = s.getAsInt();
        Verify.verify(returnCode == 0, "Call to Libsodium failed, return code was " + returnCode);
    }

}
