package com.kerosene.common.security.workload;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SpiffeX509IdentityConfigTest {

    private static final String AUTH_ID = "spiffe://staging.kerosene.internal/service/auth";
    private static final String KFE_ID = "spiffe://staging.kerosene.internal/service/kfe";

    @Test
    void rejectsNonUnixWorkloadApiBeforeConnecting() {
        WorkloadIdentityConfig config = new WorkloadIdentityConfig(
                true, "tcp://spire:8081", AUTH_ID, KFE_ID, 8443, Duration.ofSeconds(1));

        assertThrows(IllegalStateException.class, () -> new SpiffeX509Identity(config));
    }

    @Test
    void rejectsSameIdentityForBothSidesBeforeConnecting() {
        WorkloadIdentityConfig config = new WorkloadIdentityConfig(
                true, "unix:///run/spire.sock", AUTH_ID, AUTH_ID, 8443, Duration.ofSeconds(1));

        assertThrows(IllegalStateException.class, () -> new SpiffeX509Identity(config));
    }

    @Test
    void rejectsInvalidPortAndTimeoutBeforeConnecting() {
        WorkloadIdentityConfig invalidPort = new WorkloadIdentityConfig(
                true, "unix:///run/spire.sock", AUTH_ID, KFE_ID, 443, Duration.ofSeconds(1));
        WorkloadIdentityConfig invalidTimeout = new WorkloadIdentityConfig(
                true, "unix:///run/spire.sock", AUTH_ID, KFE_ID, 8443, Duration.ZERO);

        assertThrows(IllegalStateException.class, () -> new SpiffeX509Identity(invalidPort));
        assertThrows(IllegalStateException.class, () -> new SpiffeX509Identity(invalidTimeout));
    }
}
