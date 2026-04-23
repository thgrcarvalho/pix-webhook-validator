package io.github.thgrcarvalho.pixwebhook;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class PixWebhookValidatorTest {

    // ── HMAC Signature ────────────────────────────────────────────────────────

    @Nested
    class HmacTests {

        private static final String SECRET = "test-secret";
        private static final String PAYLOAD = "{\"pix\":[{\"txid\":\"abc\"}]}";

        private final PixWebhookValidator validator = PixWebhookValidator.builder()
                .hmacSecret(SECRET)
                .build();

        @Test
        void validSignature_passes() {
            String sig = computeHmac(SECRET, PAYLOAD);
            PixWebhookRequest req = request().body(PAYLOAD).header("X-Pix-Signature", sig).build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void invalidSignature_throws() {
            PixWebhookRequest req = request().body(PAYLOAD).header("X-Pix-Signature", "badhex").build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void missingSignatureHeader_throws() {
            PixWebhookRequest req = request().body(PAYLOAD).build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void signatureWithSha256Prefix_isAccepted() {
            String sig = "sha256=" + computeHmac(SECRET, PAYLOAD);
            PixWebhookRequest req = request().body(PAYLOAD).header("X-Pix-Signature", sig).build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void uppercaseSignature_isAccepted() {
            String sig = computeHmac(SECRET, PAYLOAD).toUpperCase();
            PixWebhookRequest req = request().body(PAYLOAD).header("X-Pix-Signature", sig).build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void customSignatureHeader_isRespected() {
            PixWebhookValidator custom = PixWebhookValidator.builder()
                    .hmacSecret(SECRET)
                    .signatureHeader("X-Custom-Sig")
                    .build();
            String sig = computeHmac(SECRET, PAYLOAD);
            PixWebhookRequest req = request().body(PAYLOAD).header("X-Custom-Sig", sig).build();
            assertDoesNotThrow(() -> custom.validate(req));
        }
    }

    // ── IP Allowlist ──────────────────────────────────────────────────────────

    @Nested
    class IpAllowlistTests {

        private final PixWebhookValidator validator = PixWebhookValidator.builder()
                .allowedCidrs("192.168.1.0/24", "10.0.0.0/8")
                .build();

        @Test
        void ipInAllowedCidr_passes() {
            PixWebhookRequest req = request().sourceIp("192.168.1.100").build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void ipInSecondCidr_passes() {
            PixWebhookRequest req = request().sourceIp("10.1.2.3").build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void ipOutsideAllowedCidrs_throws() {
            PixWebhookRequest req = request().sourceIp("172.16.0.1").build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void exactNetworkAddress_passes() {
            PixWebhookRequest req = request().sourceIp("192.168.1.0").build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void broadcastAddress_passes() {
            PixWebhookRequest req = request().sourceIp("192.168.1.255").build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void missingIp_throws() {
            PixWebhookRequest req = request().sourceIp(null).build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void singleHostCidr32_works() {
            PixWebhookValidator single = PixWebhookValidator.builder()
                    .allowedCidrs("203.0.113.5/32")
                    .build();
            assertDoesNotThrow(() -> single.validate(request().sourceIp("203.0.113.5").build()));
            assertThrows(PixWebhookValidationException.class,
                    () -> single.validate(request().sourceIp("203.0.113.6").build()));
        }

        @Test
        void invalidCidr_throwsOnBuild() {
            assertThrows(IllegalArgumentException.class, () ->
                    PixWebhookValidator.builder().allowedCidrs("not-a-cidr").build());
        }
    }

    // ── Timestamp / Replay Protection ────────────────────────────────────────

    @Nested
    class TimestampTests {

        private final PixWebhookValidator validator = PixWebhookValidator.builder()
                .maxAge(Duration.ofMinutes(5))
                .build();

        @Test
        void recentIsoTimestamp_passes() {
            Instant now = Instant.now();
            PixWebhookRequest req = request()
                    .header("X-Pix-Timestamp", now.toString())
                    .receivedAt(now.plusSeconds(30))
                    .build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void recentEpochTimestamp_passes() {
            Instant now = Instant.now();
            PixWebhookRequest req = request()
                    .header("X-Pix-Timestamp", String.valueOf(now.getEpochSecond()))
                    .receivedAt(now.plusSeconds(10))
                    .build();
            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void tooOldTimestamp_throws() {
            Instant fiveMinutesAgo = Instant.now().minus(Duration.ofMinutes(6));
            PixWebhookRequest req = request()
                    .header("X-Pix-Timestamp", fiveMinutesAgo.toString())
                    .build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void futureTimestamp_throws() {
            Instant future = Instant.now().plus(Duration.ofMinutes(10));
            PixWebhookRequest req = request()
                    .header("X-Pix-Timestamp", future.toString())
                    .build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void missingTimestampHeader_throws() {
            PixWebhookRequest req = request().build();
            assertThrows(PixWebhookValidationException.class, () -> validator.validate(req));
        }

        @Test
        void customTimestampHeader_isRespected() {
            PixWebhookValidator custom = PixWebhookValidator.builder()
                    .maxAge(Duration.ofMinutes(5))
                    .timestampHeader("X-Timestamp")
                    .build();
            Instant now = Instant.now();
            PixWebhookRequest req = request()
                    .header("X-Timestamp", now.toString())
                    .receivedAt(now.plusSeconds(5))
                    .build();
            assertDoesNotThrow(() -> custom.validate(req));
        }
    }

    // ── Combined Validation ───────────────────────────────────────────────────

    @Nested
    class CombinedTests {

        @Test
        void allRulesPass_doesNotThrow() {
            String secret = "my-secret";
            String payload = "{\"test\":true}";
            Instant now = Instant.now();

            PixWebhookValidator validator = PixWebhookValidator.builder()
                    .hmacSecret(secret)
                    .allowedCidrs("10.0.0.0/8")
                    .maxAge(Duration.ofMinutes(5))
                    .build();

            PixWebhookRequest req = PixWebhookRequest.builder()
                    .sourceIp("10.1.2.3")
                    .body(payload)
                    .header("X-Pix-Signature", computeHmac(secret, payload))
                    .header("X-Pix-Timestamp", now.toString())
                    .receivedAt(now.plusSeconds(1))
                    .build();

            assertDoesNotThrow(() -> validator.validate(req));
        }

        @Test
        void validatorWithNoRules_alwaysPasses() {
            PixWebhookValidator noOp = PixWebhookValidator.builder().build();
            assertDoesNotThrow(() -> noOp.validate(request().build()));
        }

        @Test
        void exceptionContainsReason() {
            PixWebhookValidator validator = PixWebhookValidator.builder()
                    .allowedCidrs("10.0.0.0/8")
                    .build();
            PixWebhookValidationException ex = assertThrows(
                    PixWebhookValidationException.class,
                    () -> validator.validate(request().sourceIp("1.2.3.4").build()));
            assertNotNull(ex.getReason());
            assertTrue(ex.getReason().contains("1.2.3.4"));
        }
    }

    // ── PixWebhookRequest ─────────────────────────────────────────────────────

    @Nested
    class RequestTests {

        @Test
        void headerLookupIsCaseInsensitive() {
            PixWebhookRequest req = request()
                    .header("X-Pix-Signature", "abc")
                    .build();
            assertEquals("abc", req.header("x-pix-signature"));
            assertEquals("abc", req.header("X-PIX-SIGNATURE"));
        }

        @Test
        void nullBodyDefaultsToEmpty() {
            PixWebhookRequest req = new PixWebhookRequest(null, null, null, Instant.now());
            assertNotNull(req.body());
            assertEquals(0, req.body().length);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static PixWebhookRequest.Builder request() {
        return PixWebhookRequest.builder().receivedAt(Instant.now());
    }

    private static String computeHmac(String secret, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(payload.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
