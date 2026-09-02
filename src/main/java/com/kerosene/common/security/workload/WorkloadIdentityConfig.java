package com.kerosene.common.security.workload;

import java.time.Duration;

public record WorkloadIdentityConfig(
        boolean enabled,
        String socket,
        String ownSpiffeId,
        String peerSpiffeId,
        int internalPort,
        Duration initTimeout) {
}
