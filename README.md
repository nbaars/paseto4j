# Java implementation of PASETO: Platform-Agnostic Security Tokens
[![License](http://img.shields.io/:license-mit-blue.svg)](LICENSE)
[![Quality](https://sonarcloud.io/api/project_badges/quality_gate?project=nbaars_paseto4j)](https://sonarcloud.io/dashboard?id=nbaars_paseto4j)

Implementation of [PASETO](https://github.com/paragonie/paseto) library written in Java. This library is focused
on taking part of the encryption/decryption part of the tokens it has a little dependencies as possible. How you
construct the tokens with which JSON library is up to you. According to the specification the payload should always
be a JSON object.

# Contents
* [What is Paseto?](#what-is-paseto)
  * [Key Differences between Paseto and JWT](#key-differences-between-paseto-and-jwt)
* [Installation](#installation)

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

There are two version available in Maven Central.

## Version 2

Version 2 (the recommended version by the specification) is supported, this version depends on Libsodium
see [here](https://download.libsodium.org/doc/installation/) on how to install this library. The Dockerfile 
contains an example how to install it on a Linux based system.

Add the following dependency to your project:

```
<!-- https://mvnrepository.com/artifact/io.github.nbaars/paseto4j-version2 -->
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-version2</artifactId>
    <version>0.0.29</version>
</dependency>
```

## Version 1 

Add the following dependency to your project:

```
<!-- https://mvnrepository.com/artifact/io.github.nbaars/paseto4j-version1 -->
<dependency>
    <groupId>io.github.nbaars</groupId>
    <artifactId>paseto4j-version1</artifactId>
    <version>0.0.29</version>
</dependency>
```

## Usage

For usage see the `examples` project which shows how to use Paseto4j in action.

# Differences with other Java Paseto implementations

Why use this library over the other Java implementations?

- No dependency on any JSON library. It is a lightweight library supporting the basic Paseto operations. The rest is up-to-you.
- Easy to use API.
- Full security audited performed by Paragon Initiative Enterprises
- Available on Maven Central

# Development

`paseto-version2` needs Libsodium to be present, to avoid installing it on your local machine, you can use the following command to build it locally:

```shell
docker run -v "${HOME}"/.m2:/root/.m2 -v "${PWD}":/workspace paseto4j ./mvnw install     
 ```

