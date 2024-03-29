# Shadow Tool Spring Boot Starter

## Introduction

For use with Spring Boot applications. See [Shadow Tool](https://github.com/rabobank/shadow-tool) for more information.

## Installation

### Maven

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.rabobank.shadow_tool/shadow-tool-spring-boot-starter/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.rabobank.shadow_tool/shadow-tool-spring-boot-starter)

```xml

<dependency>
    <groupId>io.github.rabobank.shadow_tool</groupId>
    <artifactId>shadow-tool-spring-boot-starter</artifactId>
    <version>[check maven central for latest version]</version>
</dependency>
```

## Configuration Properties

The following properties can be configured in the `application.yml` file to configure the shadow flow(s).

| Property Name                                        | Type                                                         | Default Value | Description                                                                                                                                     |
|------------------------------------------------------|--------------------------------------------------------------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `shadowflow.encryption.cipher.secret`                | `String`                                                     | `null`          | The secret for encryption. Should be a 16, 24, or 32-byte string. Could be generated as follows: `openssl rand -hex 32`                         |
| `shadowflow.encryption.cipher.initialization-vector` | `String`                                                     | `null`          | The initialization vector for encryption. Should be a 12-byte string. Could be generated as follows: `openssl rand -hex 12`                     |
| `shadowflow.encryption.public-key`                   | `String`                                                     | `null`          | Base 64 encoded version of an `X509` Public Key. Used in a Cipher with algorithm `RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING`.                       |
| `shadowflow.encryption.noop`                         | `Boolean`                                                    | `false`       | Disables encryption but encodes differences as `Base64`.                                                                                        |
| `shadowflow.flows[*].percentage`                     | `Integer`                                                    | `0`           | Percentage of how many calls should be compared in the shadow flow. Should be in the range of 0-100. Zero effectively disables the shadow flow. |
| `shadowflow.flows[*].type`                           | Fully qualified class name (i.e. `your.package.RecordClass`) | n/a           | The data model which is used to compare                                                                                                         |

## Configuring Shadow Flow Beans

Shadow Flow beans can be configured in your Spring Boot application by defining properties in the `application.yml`
file. Here are the steps to configure shadow flows:

1. Define the shadow flows you want to use in your application under the `shadowflow.flows` property.
   In this example, `flow1` and `flow2` are defined as shadow flows (which you can rename to anything).
   `percentage` represents a number in the range of 0-100 of how many calls should be compared in the
   shadow flow.
   Zero effectively disables the shadow flow.
   And `type` represents the data model which is used to compare.

```yaml
shadowflow:
  flows:
    flow1:
      percentage: 50
      type: "your.package.DataClass" # This should be a fully qualified class name
    flow2:
      percentage: 75
      type: "your.package.RecordClass"
```

2. Configure the encryption options for the shadow flows under the `shadowflow.encryption property`. You can choose to
   use
   a cipher or a public key for encryption.

* To use a cipher, define the `shadowflow.encryption.cipher` property. The cipher should have a `secret` and an
  `initialization-vector`. The secret should be a 16, 24, or 32-byte string and the `initialization-vector` should be a
  12-byte string.
* To use a public key, define the `shadowflow.encryption.public-key` property. The public key should be a Base 64
  encoded
  version of an X509 Public Key.

Either set one of the following:

Cipher example: exposes bean `defaultEncryptionService` of type `EncryptionService`

```yaml 
shadowflow:
  encryption:
    cipher:
      secret: "3d7e0c4f8fbbd8d8a79e76cabc8f4e24"
      initialization-vector: "3d7e0c4f8fbb"
```

Public key example: exposes bean `publicKeyEncryptionService` of type `EncryptionService`

```yaml 
shadowflow:
  encryption:
    cipher:
      public-key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArmkP2CgDn3OsuIj1GxM3"
```

3. If you want to disable encryption but encode differences as Base64, set the `shadowflow.encryption.noop` property to
   `true`.

This exposes bean `noopEncryptionService` of type `EncryptionService`

```yaml
shadowflow:
  encryption:
    noop: true
```

## Example Configuration

Example `application.yml` configuration for a shadow flow with all possible values combined.

*NOTE:* Make sure to only configure one of `cipher`, `public-key`, or `noop`!

```yaml
shadowflow:
  flows:
    flow1:
      percentage: 50
    flow2:
      percentage: 75
  encryption:
    cipher:
      secret: "3d7e0c4f8fbbd8d8a79e76cabc8f4e24"
      initialization-vector: "3d7e0c4f8fbb"
    public-key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArmkP2CgDn3OsuIj1GxM3"
    noop: false
```

If you have done all this, a bean of type `ShadowFlow<T>` (T is the class name you defined in the `type` property) will be exposed 
for each shadow flow you defined. In this example, `ShadowFlow<DataClass>` and `ShadowFlow<RecordClass>` will be exposed.

## Example Code

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class MyService {
    private final ShadowFlow<DataClass> shadowFlow;

    @Autowired
    public MyService(final ShadowFlow<DataClass> shadowFlow) {
        this.shadowFlow = shadowFlow;
    }

    public Mono<RecordClass> myMonoInvocation() {
        // will always return the first passed argument, so a mono of RecordClass("value")
        return shadowFlow.compare(Mono.just(new RecordClass("value")), Mono.just(new RecordClass("differentValue")));
    }

    public RecordClass myInvocation() {
        // will always return the first passed argument, so RecordClass("value")
        return shadowFlow.compare(() -> new RecordClass("value"), () -> new RecordClass("differentValue"));
    }
}
```

```kotlin

import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class MyService(private val shadowFlow: ShadowFlow<DataClass>) {

    // will always return the first passed argument, so a mono of RecordClass("value")
    fun myMonoInvocation() = shadowFlow.compare(Mono.just(RecordClass("value")), Mono.just(RecordClass("differentValue")))

    // will always return the first passed argument, so RecordClass("value")
    fun myInvocation() = shadowFlow.compare({ RecordClass("value") }, { RecordClass("differentValue") })
}
```