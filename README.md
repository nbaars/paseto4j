# Java implementation of PASETO: Platform-Agnostic Security Tokens
[![License](http://img.shields.io/:license-mit-blue.svg)](LICENSE)
[![Build Status](http://img.shields.io/travis/o1egl/paseto.svg?style=flat-square)](https://travis-ci.org/o1egl/paseto)

## WARNING: IMPLEMENTATION IS A PRE-RELEASE.

Implementation of [PASETO](https://github.com/paragonie/paseto) library written in Java

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

# Contents
* [What is Paseto?](#what-is-paseto)
  * [Key Differences between Paseto and JWT](#key-differences-between-paseto-and-jwt)
* [Installation](#installation)
* [Usage](#usage)
* [Benchmarks](#benchmarks)
* [Supported Paseto Versions](#supported-paseto-versions)

# What is Paseto?

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

# Supported Paseto Versions

## Version 2
Version 2 (the recommended version by the specification) is supported for signing. 

## Version 1 
Not supported
