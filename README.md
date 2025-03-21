![Logo](https://www.oidc.se/img/oidc-logo.png)

# oidc-sweden-nimbus

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.oidc.nimbus/oidc-sweden-nimbus/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.oidc.nimbus/oidc-sweden-nimbus)

Extensions for the Nimbus OAuth2/OpenID Connect SDK covering OIDC Sweden specifications.

## About

The `oidc-sweden-nimbus` repository contains Java implementations of the extensions specified in the
[OIDC Sweden Specifications](https://www.oidc.se/specifications/). The library extends the 
[Nimbus OAuth2/OpenID Connect SDK](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk).

## API Documentation

Javadoc for the library is published under https://www.oidc.se/oidc-sweden-nimbus/apidoc.

## Downloading the Artifact

The library is published to Maven central (https://repo1.maven.org/maven2/).

Include the following dependency in your project POM to use the extensions of `oidc-sweden-nimbus`:

```
<dependency>
  <groupId>se.oidc.nimbus</groupId>
  <artifactId>oidc-sweden-nimbus</artifactId>
  <version>${oidc.sweden.version}</version>
</dependency>
```

## Building from Source

### Prerequisites

[Git](https://help.github.com/set-up-git-redirect) and the [JDK17 build](https://www.oracle.com/technetwork/java/javase/downloads).

Be sure that your `JAVA_HOME` environment variable points to the `jdk17` folder extracted from the JDK download.

### Check out sources

```
git clone git clone https://github.com/oidc-sweden/oidc-sweden-nimbus.git
```

### Build the library using Maven

```
> mvn clean install
```


---

Copyright &copy; 2023-2025, [OIDC Sweden](https://www.oidc.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
