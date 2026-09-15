/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.key.SealingSecretKey;
import org.paseto4j.paserk.types.PublicType;
import org.paseto4j.paserk.types.SecretType;

/** Executes the imported PASERK PHP reference vectors against the public API. */
class PaserkOfficialVectorTest {

  private static final List<String> RESOURCES =
      List.of(
          "k3.local.json", "k4.local.json", "k3.lid.json", "k4.lid.json",
          "k3.public.json", "k4.public.json", "k3.pid.json", "k4.pid.json",
          "k3.secret.json", "k4.secret.json", "k3.sid.json", "k4.sid.json",
          "k3.local-wrap.pie.json", "k4.local-wrap.pie.json",
          "k3.secret-wrap.pie.json", "k4.secret-wrap.pie.json",
          "k3.local-pw.json", "k4.local-pw.json",
          "k3.secret-pw.json", "k4.secret-pw.json", "k3.seal.json", "k4.seal.json");

  static Stream<Arguments> vectors() throws IOException {
    return RESOURCES.stream()
        .flatMap(
            resource -> {
              try {
                Version version = resource.startsWith("k3.") ? Version.V3 : Version.V4;
                return TestVectors.paserk("test-vectors/" + resource).stream()
                    .map(vector -> Arguments.of(version, resource, vector));
              } catch (IOException e) {
                throw new IllegalStateException("Unable to read " + resource, e);
              }
            });
  }

  @ParameterizedTest(name = "{1}: {2}")
  @MethodSource("vectors")
  void executesReferenceVector(Version version, String resource, TestVectors.TestVector vector) {
    assertAll(vector.name, () -> execute(version, resource, vector));
  }

  private static void execute(Version version, String resource, TestVectors.TestVector vector) {
    String type = resource.substring(3, resource.length() - ".json".length());
    if (type.equals("local")) {
      if (vector.expectFail) {
        assertThrows(PaserkException.class, () -> decodeLocal(version, vector.paserk));
      } else {
        assertArrayEquals(bytes(vector.key), decodeLocal(version, vector.paserk).toBytes());
        assertEquals(vector.paserk, encodeLocal(version, SecretKey.fromBytes(bytes(vector.key))));
      }
    } else if (type.equals("lid")) {
      if (vector.expectFail) {
        assertThrows(
            RuntimeException.class,
            () ->
                localId(
                    version,
                    encodeLocal(version, SecretKey.fromBytes(bytes(vector.key)))));
      } else {
        String local = encodeLocal(version, SecretKey.fromBytes(bytes(vector.key)));
        assertEquals(vector.paserk, localId(version, local));
      }
    } else if (type.equals("public")) {
      if (vector.expectFail) {
        assertThrows(PaserkException.class, () -> decodePublic(version, vector.paserk));
      } else {
        assertEquals(vector.paserk, encodePublic(version, decodePublic(version, vector.paserk)));
      }
    } else if (type.equals("pid")) {
      if (vector.expectFail) {
        assertThrows(PaserkException.class, () -> encodePublic(version, bytes(vector.key)));
      } else {
        String publicPaserk = new PublicType(version).encode(bytes(vector.key));
        assertEquals(vector.paserk, publicId(version, publicPaserk));
      }
    } else if (type.equals("secret")) {
      if (vector.expectFail) {
        assertThrows(PaserkException.class, () -> decodeSecret(version, vector.paserk));
      } else {
        assertArrayEquals(bytes(vector.key), encodeSecret(version, decodeSecret(version, vector.paserk)));
      }
    } else if (type.equals("sid")) {
      if (vector.expectFail) {
        assertThrows(
            RuntimeException.class,
            () -> decodeSecret(version, new SecretType(version).encode(bytes(vector.key))));
      } else {
        assertEquals(
            vector.paserk,
            secretId(version, new SecretType(version).encode(bytes(vector.key))));
      }
    } else if (type.endsWith("wrap.pie")) {
      executePie(version, type.startsWith("secret"), vector);
    } else if (type.endsWith("-pw")) {
      executePasswordWrap(version, type.startsWith("secret"), vector);
    } else if (type.equals("seal")) {
      executeSeal(version, vector);
    } else {
      throw new AssertionError("Unhandled reference-vector resource: " + resource);
    }
  }

  private static void executePie(
      Version version, boolean secret, TestVectors.TestVector vector) {
    WrappingKey wrappingKey = WrappingKey.fromBytes(bytes(vector.wrappingKey));
    if (vector.expectFail) {
      assertThrows(
          PaserkException.class,
          () -> {
            if (secret) {
              unwrapSecret(version, vector.paserk, wrappingKey);
            } else {
              unwrapLocal(version, vector.paserk, wrappingKey);
            }
          });
    } else {
      byte[] raw =
          secret
              ? encodeSecret(version, unwrapSecret(version, vector.paserk, wrappingKey))
              : unwrapLocal(version, vector.paserk, wrappingKey);
      assertArrayEquals(bytes(vector.unwrapped), raw);
    }
  }

  private static void executePasswordWrap(
      Version version, boolean secret, TestVectors.TestVector vector) {
    char[] password = vector.password.toCharArray();
    if (vector.expectFail) {
      assertThrows(
          PaserkException.class,
          () -> {
            if (secret) {
              unwrapSecretWithPassword(version, vector.paserk, password);
            } else {
              unwrapLocalWithPassword(version, vector.paserk, password);
            }
          });
    } else if (secret) {
      assertArrayEquals(
          bytes(vector.unwrapped),
          encodeSecret(version, unwrapSecretWithPassword(version, vector.paserk, password)));
    } else {
      assertArrayEquals(
          bytes(vector.unwrapped),
          unwrapLocalWithPassword(version, vector.paserk, password).toBytes());
    }
  }

  private static void executeSeal(Version version, TestVectors.TestVector vector) {
    if (vector.expectFail) {
      assertThrows(
          PaserkException.class,
          () ->
              unseal(
                  version,
                  vector.paserk,
                  sealingSecretKey(version, vector.sealingSecretKey)));
    } else {
      assertArrayEquals(
          bytes(vector.unsealed),
          unseal(
                  version,
                  vector.paserk,
                  sealingSecretKey(version, vector.sealingSecretKey))
              .toBytes());
    }
  }

  private static SealingSecretKey sealingSecretKey(Version version, String encoded) {
    if (encoded.startsWith("-----BEGIN")) {
      String body = encoded.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
      try {
        ASN1Sequence sequence =
            ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(Base64.getDecoder().decode(body)));
        return SealingSecretKey.from(
            KeyEncoding.decodeV3Secret(ASN1OctetString.getInstance(sequence.getObjectAt(1)).getOctets()));
      } catch (Exception e) {
        throw new AssertionError("Unable to decode reference P-384 sealing key", e);
      }
    }
    byte[] raw = bytes(encoded);
    return version == Version.V3
        ? SealingSecretKey.from(KeyEncoding.decodeV3Secret(raw))
        : SealingSecretKey.from(KeyEncoding.decodeV4Secret(raw));
  }

  private static byte[] bytes(String hex) {
    return HexToBytes.hexToBytes(hex);
  }

  private static SecretKey decodeLocal(Version v, String paserk) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.decodeLocal(paserk)
        : org.paseto4j.paserk.version4.Paserk.decodeLocal(paserk);
  }

  private static String encodeLocal(Version v, SecretKey key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.encodeLocal(key)
        : org.paseto4j.paserk.version4.Paserk.encodeLocal(key);
  }

  private static String localId(Version v, String key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.localId(key)
        : org.paseto4j.paserk.version4.Paserk.localId(key);
  }

  private static Object decodePublic(Version v, String paserk) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.decodePublicKey(paserk)
        : org.paseto4j.paserk.version4.Paserk.decodePublicKey(paserk);
  }

  private static String encodePublic(Version v, Object key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.encodePublicKey((java.security.interfaces.ECPublicKey) key)
        : org.paseto4j.paserk.version4.Paserk.encodePublicKey((java.security.interfaces.EdECPublicKey) key);
  }

  private static String encodePublic(Version v, byte[] raw) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.encodePublicKey(KeyEncoding.decodeV3Public(raw))
        : org.paseto4j.paserk.version4.Paserk.encodePublicKey(KeyEncoding.decodeV4Public(raw));
  }

  private static String publicId(Version v, String key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.publicKeyId(
            org.paseto4j.paserk.version3.Paserk.decodePublicKey(key))
        : org.paseto4j.paserk.version4.Paserk.publicKeyId(
            org.paseto4j.paserk.version4.Paserk.decodePublicKey(key));
  }

  private static Object decodeSecret(Version v, String paserk) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.decodeSecretKey(paserk)
        : org.paseto4j.paserk.version4.Paserk.decodeSecretKey(paserk);
  }

  private static byte[] encodeSecret(Version v, Object key) {
    return v == Version.V3
        ? KeyEncoding.encodeV3Secret((ECPrivateKey) key)
        : KeyEncoding.encodeV4Secret((EdECPrivateKey) key);
  }

  private static String secretId(Version v, String key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.secretKeyId(key)
        : org.paseto4j.paserk.version4.Paserk.secretKeyId(key);
  }

  private static byte[] unwrapLocal(Version v, String paserk, WrappingKey key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.unwrapLocal(paserk, key).toBytes()
        : org.paseto4j.paserk.version4.Paserk.unwrapLocal(paserk, key).toBytes();
  }

  private static Object unwrapSecret(Version v, String paserk, WrappingKey key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.unwrapSecret(paserk, key)
        : org.paseto4j.paserk.version4.Paserk.unwrapSecret(paserk, key);
  }

  private static SecretKey unwrapLocalWithPassword(Version v, String paserk, char[] password) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.unwrapLocalWithPassword(paserk, password)
        : org.paseto4j.paserk.version4.Paserk.unwrapLocalWithPassword(paserk, password);
  }

  private static Object unwrapSecretWithPassword(Version v, String paserk, char[] password) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.unwrapSecretWithPassword(paserk, password)
        : org.paseto4j.paserk.version4.Paserk.unwrapSecretWithPassword(paserk, password);
  }

  private static SecretKey unseal(Version v, String paserk, SealingSecretKey key) {
    return v == Version.V3
        ? org.paseto4j.paserk.version3.Paserk.unseal(paserk, key)
        : org.paseto4j.paserk.version4.Paserk.unseal(paserk, key);
  }
}
