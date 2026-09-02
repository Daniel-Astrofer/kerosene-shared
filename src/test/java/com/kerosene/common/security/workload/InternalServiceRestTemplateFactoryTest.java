package com.kerosene.common.security.workload;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InternalServiceRestTemplateFactoryTest {

    @Test
    void mtlsClientRejectsClearTextAndMissingIdentity() {
        WorkloadIdentityConfig config = new WorkloadIdentityConfig(
                true,
                "unix:///run/spire.sock",
                "spiffe://staging.kerosene.internal/service/auth",
                "spiffe://staging.kerosene.internal/service/kfe",
                8443,
                Duration.ofSeconds(1));
        InternalServiceRestTemplateFactory factory =
                new InternalServiceRestTemplateFactory(config, null, "");

        assertThrows(IllegalStateException.class,
                () -> factory.create("http://kfe:8080", "", 100, 100));
        assertThrows(IllegalStateException.class,
                () -> factory.create("https://kfe:8443", "", 100, 100));
    }

    @Test
    void legacyClientNormalizesTrailingSlash() {
        WorkloadIdentityConfig config = new WorkloadIdentityConfig(
                false, "", "", "", 8443, Duration.ofSeconds(1));
        InternalServiceRestTemplateFactory factory =
                new InternalServiceRestTemplateFactory(config, null, "credential");

        InternalServiceRestTemplateFactory.ConfiguredClient client =
                factory.create("http://kfe:8080/", "", 100, 100);

        assertEquals("http://kfe:8080", client.baseUrl());
    }
}
