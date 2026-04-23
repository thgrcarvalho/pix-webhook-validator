package io.github.thgrcarvalho.pixwebhook;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * A framework-agnostic snapshot of an incoming Pix webhook request.
 *
 * <p>Construct from your framework's request object and pass to
 * {@link PixWebhookValidator#validate(PixWebhookRequest)}:</p>
 *
 * <pre>{@code
 * // Spring MVC example
 * PixWebhookRequest req = PixWebhookRequest.builder()
 *     .sourceIp(request.getRemoteAddr())
 *     .header("X-Pix-Signature", request.getHeader("X-Pix-Signature"))
 *     .body(request.getInputStream().readAllBytes())
 *     .receivedAt(Instant.now())
 *     .build();
 * }</pre>
 *
 * @param sourceIp    the IP address of the request sender
 * @param headers     the relevant request headers (case-insensitive lookup recommended)
 * @param body        the raw request body bytes
 * @param receivedAt  when the request was received (used for replay-protection checks)
 */
public record PixWebhookRequest(
        String sourceIp,
        Map<String, String> headers,
        byte[] body,
        Instant receivedAt
) {

    public PixWebhookRequest {
        Objects.requireNonNull(receivedAt, "receivedAt must not be null");
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        body = body == null ? new byte[0] : body.clone();
    }

    /** Returns the value of the named header, case-insensitively, or {@code null}. */
    public String header(String name) {
        if (headers == null || name == null) return null;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String sourceIp;
        private final java.util.LinkedHashMap<String, String> headers = new java.util.LinkedHashMap<>();
        private byte[] body;
        private Instant receivedAt = Instant.now();

        public Builder sourceIp(String sourceIp) { this.sourceIp = sourceIp; return this; }
        public Builder header(String name, String value) { headers.put(name, value); return this; }
        public Builder headers(Map<String, String> h) { headers.putAll(h); return this; }
        public Builder body(byte[] body) { this.body = body; return this; }
        public Builder body(String body) { this.body = body.getBytes(java.nio.charset.StandardCharsets.UTF_8); return this; }
        public Builder receivedAt(Instant receivedAt) { this.receivedAt = receivedAt; return this; }

        public PixWebhookRequest build() {
            return new PixWebhookRequest(sourceIp, headers, body, receivedAt);
        }
    }
}
