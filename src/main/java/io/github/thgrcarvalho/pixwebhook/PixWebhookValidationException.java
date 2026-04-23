package io.github.thgrcarvalho.pixwebhook;

/**
 * Thrown when a Pix webhook request fails validation.
 * The message describes which check failed and why.
 */
public class PixWebhookValidationException extends RuntimeException {

    private final String reason;

    public PixWebhookValidationException(String reason) {
        super(reason);
        this.reason = reason;
    }

    /**
     * Returns the specific validation failure reason, suitable for logging.
     * Do not expose this in HTTP responses — it may reveal security configuration.
     *
     * @return the failure reason
     */
    public String getReason() {
        return reason;
    }
}
