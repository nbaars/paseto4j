package org.paseto4j.version4;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class CryptoFunctions {
  private CryptoFunctions() {}

  public static byte[] xchacha20(byte[] message, byte[] nonce, byte[] key) {
    XChaCha20Engine engine = new XChaCha20Engine();

    engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
    byte[] out = new byte[message.length];

    engine.processBytes(message, 0, message.length, out, 0);

    return out;
  }

  public static byte[] blake2b(int size, byte[] message, byte[] key) {
    Digest digest = new Blake2bDigest(key, size, null, null);
    byte[] out = new byte[size];
    digest.update(message, 0, message.length);
    digest.doFinal(out, 0);
    return out;
  }

  public static byte[] sign(PrivateKey privateKey, byte[] msg) {
    try {
      Signature signature = Signature.getInstance("Ed25519", "BC");
      signature.initSign(privateKey);
      signature.update(msg);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature) {
    try {
      Signature verifier = Signature.getInstance("Ed25519", "BC");
      verifier.initVerify(publicKey);
      verifier.update(msg);

      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
