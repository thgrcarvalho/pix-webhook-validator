package io.github.thgrcarvalho.pixwebhook;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Validates incoming Pix webhook requests against configurable security rules.
 *
 * <p>Configure once with the builder and call {@link #validate} per request:</p>
 *
 * <pre>{@code
 * private final PixWebhookValidator validator = PixWebhookValidator.builder()
 *     .hmacSecret("your-shared-secret")          // validates X-Pix-Signature header
 *     .allowedCidrs("177.71.207.0/24")           // EfiBank production IPs
 *     .maxAge(Duration.ofMinutes(5))             // replay protection
 *     .timestampHeader("X-Pix-Timestamp")        // header carrying the request timestamp
 *     .build();
 *
 * // In your webhook controller
 * validator.validate(
 *     PixWebhookRequest.builder()
 *         .sourceIp(request.getRemoteAddr())
 *         .header("X-Pix-Signature", request.getHeader("X-Pix-Signature"))
 *         .header("X-Pix-Timestamp", request.getHeader("X-Pix-Timestamp"))
 *         .body(request.getInputStream().readAllBytes())
 *         .build()
 * );
 * }</pre>
 *
 * <p>Throws {@link PixWebhookValidationException} if any enabled check fails.
 * Callers should catch this exception and respond with HTTP 401 or 403.</p>
 */
public final class PixWebhookValidator {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String DEFAULT_SIGNATURE_HEADER = "X-Pix-Signature";
    private static final String DEFAULT_TIMESTAMP_HEADER = "X-Pix-Timestamp";

    private final byte[] hmacSecretBytes;
    private final String signatureHeader;
    private final List<CidrBlock> allowedCidrs;
    private final Duration maxAge;
    private final String timestampHeader;

    private PixWebhookValidator(Builder builder) {
        this.hmacSecretBytes = builder.hmacSecret != null
                ? builder.hmacSecret.getBytes(StandardCharsets.UTF_8) : null;
        this.signatureHeader = builder.signatureHeader;
        this.allowedCidrs = List.copyOf(builder.allowedCidrs);
        this.maxAge = builder.maxAge;
        this.timestampHeader = builder.timestampHeader;
    }

    /**
     * Validates {@code request} against all configured rules.
     *
     * @param request the incoming webhook request
     * @throws PixWebhookValidationException if any check fails
     * @throws NullPointerException          if {@code request} is null
     */
    public void validate(PixWebhookRequest request) {
        Objects.requireNonNull(request, "request must not be null");

        if (!allowedCidrs.isEmpty()) {
            validateIp(request.sourceIp());
        }
        if (maxAge != null) {
            validateTimestamp(request);
        }
        if (hmacSecretBytes != null) {
            validateHmac(request);
        }
    }

    // ── IP allowlist ─────────────────────────────────────────────────────────

    private void validateIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new PixWebhookValidationException("Source IP is missing");
        }
        try {
            InetAddress addr = InetAddress.getByName(sourceIp);
            for (CidrBlock cidr : allowedCidrs) {
                if (cidr.contains(addr)) return;
            }
        } catch (UnknownHostException e) {
            throw new PixWebhookValidationException("Source IP is invalid: " + sourceIp);
        }
        throw new PixWebhookValidationException("Source IP not in allowlist: " + sourceIp);
    }

    // ── Timestamp / replay protection ────────────────────────────────────────

    private void validateTimestamp(PixWebhookRequest request) {
        String headerValue = request.header(timestampHeader);
        if (headerValue == null || headerValue.isBlank()) {
            throw new PixWebhookValidationException(
                    "Missing required timestamp header: " + timestampHeader);
        }
        Instant requestTime;
        try {
            // Support both ISO-8601 ("2024-01-15T10:00:00Z") and Unix epoch seconds ("1705312800")
            requestTime = headerValue.contains("T")
                    ? Instant.parse(headerValue)
                    : Instant.ofEpochSecond(Long.parseLong(headerValue));
        } catch (Exception e) {
            throw new PixWebhookValidationException(
                    "Unparseable timestamp in header " + timestampHeader + ": " + headerValue);
        }
        Duration age = Duration.between(requestTime, request.receivedAt()).abs();
        if (age.compareTo(maxAge) > 0) {
            throw new PixWebhookValidationException(
                    "Request timestamp is too old or too far in the future (age=" + age.getSeconds() + "s, max=" + maxAge.getSeconds() + "s)");
        }
    }

    // ── HMAC-SHA256 signature ─────────────────────────────────────────────────

    private void validateHmac(PixWebhookRequest request) {
        String provided = request.header(signatureHeader);
        if (provided == null || provided.isBlank()) {
            throw new PixWebhookValidationException(
                    "Missing required signature header: " + signatureHeader);
        }
        String expected = computeHmac(request.body());
        // Constant-time comparison to prevent timing attacks
        if (!constantTimeEquals(expected, normalise(provided))) {
            throw new PixWebhookValidationException("HMAC signature mismatch");
        }
    }

    private String computeHmac(byte[] body) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(hmacSecretBytes, HMAC_ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(body));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Failed to compute HMAC", e);
        }
    }

    /** Strips common prefixes like "sha256=" that some providers prepend. */
    private static String normalise(String signature) {
        int eq = signature.indexOf('=');
        return eq >= 0 ? signature.substring(eq + 1).toLowerCase() : signature.toLowerCase();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    // ── CIDR ─────────────────────────────────────────────────────────────────

    private record CidrBlock(byte[] network, int prefixLength, int addressLength) {
        static CidrBlock parse(String cidr) {
            String[] parts = cidr.split("/");
            try {
                InetAddress addr = InetAddress.getByName(parts[0]);
                int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : addr.getAddress().length * 8;
                return new CidrBlock(addr.getAddress(), prefix, addr.getAddress().length);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Invalid CIDR block: " + cidr, e);
            }
        }

        boolean contains(InetAddress address) {
            byte[] candidate = address.getAddress();
            if (candidate.length != addressLength) return false;
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (network[i] != candidate[i]) return false;
            }
            if (remainingBits > 0) {
                int mask = 0xFF << (8 - remainingBits) & 0xFF;
                if ((network[fullBytes] & mask) != (candidate[fullBytes] & mask)) return false;
            }
            return true;
        }
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String hmacSecret;
        private String signatureHeader = DEFAULT_SIGNATURE_HEADER;
        private final List<CidrBlock> allowedCidrs = new ArrayList<>();
        private Duration maxAge;
        private String timestampHeader = DEFAULT_TIMESTAMP_HEADER;

        /**
         * Enables HMAC-SHA256 signature validation.
         * The computed hex digest is compared against the {@code X-Pix-Signature} header
         * (or the header configured via {@link #signatureHeader}).
         *
         * @param secret the shared HMAC secret
         * @return this builder
         */
        public Builder hmacSecret(String secret) {
            this.hmacSecret = Objects.requireNonNull(secret, "secret must not be null");
            return this;
        }

        /**
         * Overrides the header name used for signature validation (default: {@code X-Pix-Signature}).
         *
         * @param headerName the header name
         * @return this builder
         */
        public Builder signatureHeader(String headerName) {
            this.signatureHeader = headerName;
            return this;
        }

        /**
         * Restricts accepted requests to the given CIDR ranges.
         * IPv4 and IPv6 ranges are both supported.
         *
         * @param cidrs one or more CIDR blocks, e.g. {@code "177.71.207.0/24"}
         * @return this builder
         */
        public Builder allowedCidrs(String... cidrs) {
            for (String cidr : cidrs) {
                allowedCidrs.add(CidrBlock.parse(cidr));
            }
            return this;
        }

        /**
         * Enables replay-attack protection by rejecting requests whose timestamp
         * header is older than {@code maxAge} from now.
         *
         * @param maxAge maximum acceptable request age
         * @return this builder
         */
        public Builder maxAge(Duration maxAge) {
            this.maxAge = maxAge;
            return this;
        }

        /**
         * Overrides the header name used for timestamp validation (default: {@code X-Pix-Timestamp}).
         *
         * @param headerName the header name
         * @return this builder
         */
        public Builder timestampHeader(String headerName) {
            this.timestampHeader = headerName;
            return this;
        }

        /**
         * Builds the validator. At least one validation rule should be enabled;
         * a validator with no rules configured will always pass.
         *
         * @return the configured validator
         */
        public PixWebhookValidator build() {
            return new PixWebhookValidator(this);
        }
    }
}
