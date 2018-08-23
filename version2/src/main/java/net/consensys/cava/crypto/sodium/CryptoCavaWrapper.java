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

import java.util.function.Supplier;
import java.util.stream.IntStream;

/**
 * Class for exposing underlying generich hash for blake2b.
 * <p>
 * Necessary as by default {@link Sodium#crypto_generichash_blake2b} is defined as package-private
 */
public class CryptoCavaWrapper {

    private CryptoCavaWrapper() {
    }

    public static void crypto_generichash_blake2b(byte[] out, byte[] in, byte[] key) {
        runIt(() -> Sodium.crypto_generichash_blake2b(out, out.length, in, in.length, key, key.length));
    }

    public static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        Sodium.randombytes(result, length);

        Verify.verify(!isEmpty(result), "Random generation failed, contains all zeroes");

        return result;
    }

    public static void crypto_sign_detached(byte[] out, byte[] msg, byte[] privateKey) {
        runIt(() -> Sodium.crypto_sign_detached(out, new LongLongByReference(), msg, msg.length, privateKey));
    }

    public static void crypto_sign_ed25519_seed_keypair(byte[] seed, byte[] pkey, byte[] sk) {
        runIt(() -> Sodium.crypto_sign_ed25519_seed_keypair(pkey, sk, seed));
    }

    public static int crypto_sign_verify_detached(byte[] signature, byte[] message, byte[] publicKey) {
        return Sodium.crypto_sign_verify_detached(signature, message, message.length, publicKey);
    }

    static boolean isEmpty(final byte[] data) {
        return IntStream.range(0, data.length).parallel().allMatch(i -> data[i] == 0);
    }

    private static void runIt(Supplier<Integer> s) {
        int returnCode = s.get();
        Verify.verify(returnCode == 0, "Call to Libsodium failed, return code was " + returnCode);
    }

}
