# pix-webhook-validator

[![CI](https://github.com/thgrcarvalho/pix-webhook-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/thgrcarvalho/pix-webhook-validator/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.thgrcarvalho/pix-webhook-validator)](https://central.sonatype.com/artifact/io.github.thgrcarvalho/pix-webhook-validator)
[![codecov](https://codecov.io/gh/thgrcarvalho/pix-webhook-validator/branch/main/graph/badge.svg)](https://codecov.io/gh/thgrcarvalho/pix-webhook-validator)

Zero-dependency Java 21 library for validating incoming Pix webhook requests. Combines three defences: **HMAC-SHA256 signature** (prevents tampering), **IP allowlist with CIDR** (restricts to provider IPs), and **timestamp window** (prevents replay attacks).

## Installation

**Gradle:**
```groovy
dependencies {
    implementation 'io.github.thgrcarvalho:pix-webhook-validator:0.1.0'
}
```

**Maven:**
```xml
<dependency>
    <groupId>io.github.thgrcarvalho</groupId>
    <artifactId>pix-webhook-validator</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

Configure once, validate per request:

```java
// Configure (e.g. in a Spring @Configuration or as a static field)
PixWebhookValidator validator = PixWebhookValidator.builder()
    .hmacSecret("your-shared-secret")             // validates X-Pix-Signature
    .allowedCidrs("177.71.207.0/24")              // EfiBank production IPs
    .maxAge(Duration.ofMinutes(5))                // replay protection
    .build();

// In your controller
@PostMapping("/webhooks/pix")
public ResponseEntity<Void> handleWebhook(HttpServletRequest request) throws IOException {
    byte[] body = request.getInputStream().readAllBytes();
    try {
        validator.validate(
            PixWebhookRequest.builder()
                .sourceIp(request.getRemoteAddr())
                .header("X-Pix-Signature", request.getHeader("X-Pix-Signature"))
                .header("X-Pix-Timestamp", request.getHeader("X-Pix-Timestamp"))
                .body(body)
                .build()
        );
    } catch (PixWebhookValidationException e) {
        // Log e.getReason() internally — do NOT expose it in the response
        return ResponseEntity.status(401).build();
    }
    // process body...
    return ResponseEntity.ok().build();
}
```

## Validation rules

All rules are optional. Enable only what your provider supports.

| Rule | Builder method | What it checks |
|------|---------------|----------------|
| HMAC signature | `.hmacSecret("...")` | `X-Pix-Signature` header = HMAC-SHA256(secret, body). Accepts `sha256=` prefix. Case-insensitive. |
| IP allowlist | `.allowedCidrs("10.0.0.0/8", ...)` | Source IP is within one of the given CIDR blocks. IPv4 and IPv6 supported. |
| Timestamp | `.maxAge(Duration.ofMinutes(5))` | `X-Pix-Timestamp` header is within ±maxAge of now. Accepts ISO-8601 and Unix epoch seconds. |

Header names are configurable via `.signatureHeader(name)` and `.timestampHeader(name)`.

## Security notes

- **Never expose `PixWebhookValidationException.getReason()`** in HTTP responses — it may reveal your security configuration to an attacker.
- **Use constant-time comparison** (already built-in) to prevent timing attacks on HMAC validation.
- **Combine all three rules** for defence in depth. IP allowlist alone is bypassable if the attacker can spoof or route through an allowed IP.

## Running tests

```bash
./gradlew test
```

## Tech

Java 21 · Zero dependencies · Gradle · JUnit 5
