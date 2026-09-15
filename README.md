# Java implementation of PASETO: Platform-Agnostic Security Tokens

[![License](http://img.shields.io/:license-mit-blue.svg)](LICENSE)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=nbaars_paseto4j&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=nbaars_paseto4j)
[![GitHub release](https://img.shields.io/github/release/nbaars/paseto4j.svg)](https://github.com/nbaars/paseto4j/releases/latest)
[![java-jdk](https://img.shields.io/badge/java%20jdk-21-green.svg)](https://jdk.java.net/)
[![Build](https://github.com/nbaars/paseto4j/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nbaars/paseto4j/actions/workflows/build.yml)

Implementation of [PASETO](https://github.com/paragonie/paseto) library written in Java. This library is focused
on taking part of the encryption/decryption part of the tokens it has a little dependencies as possible. How you
construct the tokens with which JSON library is up to you. According to the specification the payload should always
be a JSON object.

# Contents

* [What is Paseto?](#what-is-paseto)
  * [Key Differences between Paseto and JWT](#key-differences-between-paseto-and-jwt)
* [Installation](#installation)
  * [PASERK](#paserk)

# What is Paseto?

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).
Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

## Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, Paseto only allows secure operations. JWT gives you "algorithm agility",
Paseto gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use Paseto in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor Paseto were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> Paseto is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself

# Installation

There are four PASETO versions available in Maven Central.

## Version 4

Add the following dependency to your project:

```
<!-- https://mvnrepository.com/artifact/io.github.nbaars/paseto4j-version4 -->
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-version4</artifactId>
    <version>${paseto4j.version}</version>
</dependency>
```

## Version 3

Version 3 is composed of NIST-approved algorithms, and will operate on tokens with the *v3* version header.

Add the following dependency to your project:

```
<!-- https://mvnrepository.com/artifact/io.github.nbaars/paseto4j-version3 -->
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-version3</artifactId>
    <version>${paseto4j.version}</version>
</dependency>
```

## Version 2

[Version 2 is deprecated](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md)
by the PASETO specification. New applications should use Version 4. Version 2 remains supported for backward
compatibility and depends on Libsodium; see [here](https://download.libsodium.org/doc/installation/) for installation
instructions. The Dockerfile contains an example of how to install it on a Linux-based system.

Add the following dependency to your project:

```
<!-- https://mvnrepository.com/artifact/io.github.nbaars/paseto4j-version2 -->
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-version2</artifactId>
    <version>${paseto4j.version}</version>
</dependency>
```

## Version 1

Add the following dependency to your project:

```
<!-- https://mvnrepository.com/artifact/io.github.nbaars/paseto4j-version1 -->
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-version1</artifactId>
    <version>${paseto4j.version}</version>
</dependency>
```

## PASERK

[PASERK](https://github.com/paseto-standard/paserk) key serialization and wrapping is available as an optional
module for PASETO versions 3 and 4:

```xml
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-paserk</artifactId>
    <version>${paseto4j.version}</version>
</dependency>
```

Each supported version has a static entry class matching the PASETO API style. For example, with version 4:

```java
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.operations.key.SealingSecretKey;
import org.paseto4j.paserk.version4.Paserk;

SecretKey localKey = SecretKey.fromHexString(keyHex);
String encoded = Paserk.encodeLocal(localKey);
SecretKey decoded = Paserk.decodeLocal(encoded);

SealingSecretKey sealingKey = SealingSecretKey.generate(Version.V4);
String sealed = Paserk.seal(localKey, sealingKey.publicKey());
SecretKey unsealed = Paserk.unseal(sealed, sealingKey);
```

The module supports `local`, `public`, `secret`, `lid`, `pid`, `sid`, password wrapping, PIE wrapping, and sealing.
Sealing keys are deliberately distinct from signing keys to discourage key reuse. The version 3 API is available
from `org.paseto4j.paserk.version3.Paserk`.

## Usage

For usage see the `examples` project which shows how to use Paseto4j in action.

# Differences with other Java Paseto implementations

Why use this library over the other Java implementations?

- No dependency on any JSON library. It is a lightweight library supporting the basic Paseto operations. The rest is up-to-you.
- Easy to use API.
- Available on Maven Central

## Example usages

- https://nutbutterfly.medium.com/spring-boot-quick-guide-to-replace-jwt-with-paseto-774f43c8f2c4 - This library provide a simple API, easy to use and fully flexible for developer.

# Development

This project now requires JDK 21 or newer to build and run.

`paseto-version2` needs Libsodium to be present, to avoid installing it on your local machine, you can use the following command to build it locally:

```shell
docker build -t paseto4j .
docker run -v "${HOME}"/.m2:/root/.m2 -v "${PWD}":/workspace paseto4j ./mvnw verify     
```

The first command is only necessary ones, for building the Maven image.

Another way to run it locally is to first (macOS only):

```
brew install libsodium
```

Then run `./mvnw verify` to run the tests and build the project.

# Release

We use [Calendar Versioning](https://calver.org/) as version numbers. Creating a new tag and pushing it to GitHub will start the release process.
