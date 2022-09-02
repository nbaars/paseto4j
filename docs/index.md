---
layout: default
---

# What is Paseto?

Paseto (**P**latform-**A**gnostic **SE**curity **TO**kens) is a specification and reference implementation for secure stateless tokens.

# Usage

Using the library is easy; choose which version you want to use and add it to the project. The latest version can be found [here](https://mvnrepository.com/artifact/io.github.nbaars)

## Add to project

Paseto consists of multiple versions, in Paseto4j all the versions are packaged in different jar files.

Add this version to your project. For example, for Maven, you can add:

```xml
<dependency>
  <groupId>io.github.nbaars</groupId>
  <artifactId>paseto4j-version{1,2,3}</artifactId>
  <version>${paseto4j.version}</version>
</dependency>
```

## Using V{1,2,3}.local

Each version works in the same way:

```java
private static final String TOKEN = "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}";
private static final String FOOTER = "Paragon Initiative Enterprises";

byte[] secretKey = ... 
        
var encryptedToken = Paseto.encrypt(new SecretKey(secretKey, V1), TOKEN, FOOTER);
Paseto.decrypt(new SecretKey(secretKey, V1), encryptedToken, FOOTER);
```

The `footer` is optional and will default to `""`. Version 3 supports an implicit assertion as well, which is optional and will default to `""`.

## Using V{1,2,3}.public

Each version works in the same way:

```java
private static final String TOKEN = "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}";
private static final String FOOTER = "Paragon Initiative Enterprises";

var signedToken = Paseto.sign(new PrivateKey(privateKey, V1), TOKEN, FOOTER);
Paseto.parse(new PublicKey(publicKey, V1), signedToken, FOOTER);x
```
