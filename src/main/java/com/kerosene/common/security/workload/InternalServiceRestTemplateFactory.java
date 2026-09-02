package com.kerosene.common.security.workload;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

public final class InternalServiceRestTemplateFactory {

    public static final String LEGACY_HEADER = "X-KFE-Internal-Secret";

    private final WorkloadIdentityConfig config;
    private final SpiffeX509Identity spiffeIdentity;
    private final String legacySecret;

    public InternalServiceRestTemplateFactory(
            WorkloadIdentityConfig config,
            SpiffeX509Identity spiffeIdentity,
            String legacySecret) {
        this.config = config;
        this.spiffeIdentity = spiffeIdentity;
        this.legacySecret = legacySecret;
    }

    public ConfiguredClient create(String rawBaseUrl, String defaultBaseUrl, long connectTimeoutMs, long readTimeoutMs) {
        String baseUrl = normalize(rawBaseUrl, defaultBaseUrl);
        Duration connectTimeout = positiveDuration(connectTimeoutMs, "connect timeout");
        Duration readTimeout = positiveDuration(readTimeoutMs, "read timeout");

        SimpleClientHttpRequestFactory requestFactory;
        if (config.enabled()) {
            if (!baseUrl.startsWith("https://")) {
                throw new IllegalStateException("SPIFFE internal client requires an https:// base URL");
            }
            if (spiffeIdentity == null) {
                throw new IllegalStateException("SPIFFE identity is unavailable");
            }
            requestFactory = new SpiffeClientHttpRequestFactory(spiffeIdentity.peerSslContext());
        } else {
            requestFactory = new SimpleClientHttpRequestFactory();
        }
        requestFactory.setConnectTimeout(connectTimeout);
        requestFactory.setReadTimeout(readTimeout);

        RestTemplate restTemplate = new RestTemplate(requestFactory);
        if (!config.enabled()) {
            restTemplate.getInterceptors().add((request, body, execution) -> {
                if (legacySecret == null || legacySecret.isBlank()) {
                    throw new IllegalStateException(
                            "internal shared secret must be configured when workload identity is disabled");
                }
                request.getHeaders().set(LEGACY_HEADER, legacySecret);
                return execution.execute(request, body);
            });
        }
        return new ConfiguredClient(restTemplate, baseUrl);
    }

    private static Duration positiveDuration(long millis, String name) {
        if (millis <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return Duration.ofMillis(millis);
    }

    private static String normalize(String raw, String fallback) {
        String value = raw == null || raw.isBlank() ? fallback : raw.trim();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public record ConfiguredClient(RestTemplate restTemplate, String baseUrl) {
    }
}
