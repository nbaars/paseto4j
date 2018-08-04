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
