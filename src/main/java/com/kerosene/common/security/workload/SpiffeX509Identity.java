package com.kerosene.common.security.workload;

import io.spiffe.provider.SpiffeSslContextFactory;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.DefaultX509Source;

import javax.net.ssl.SSLContext;
import java.util.Set;

public final class SpiffeX509Identity implements AutoCloseable {

    private final DefaultX509Source source;
    private final SSLContext peerSslContext;

    public SpiffeX509Identity(WorkloadIdentityConfig config) {
        requireText(config.socket(), "workload identity socket");
        requireText(config.ownSpiffeId(), "own SPIFFE ID");
        requireText(config.peerSpiffeId(), "peer SPIFFE ID");
        if (!config.socket().startsWith("unix://")) {
            throw new IllegalStateException("workload identity socket must use a unix:// endpoint");
        }
        if (config.initTimeout() == null || config.initTimeout().isZero() || config.initTimeout().isNegative()) {
            throw new IllegalStateException("workload identity init timeout must be positive");
        }
        if (config.internalPort() < 1024 || config.internalPort() > 65535) {
            throw new IllegalStateException("internal mTLS port must be between 1024 and 65535");
        }

        SpiffeId ownId = parse(config.ownSpiffeId(), "own SPIFFE ID");
        SpiffeId peerId = parse(config.peerSpiffeId(), "peer SPIFFE ID");
        if (ownId.equals(peerId)) {
            throw new IllegalStateException("own and peer SPIFFE IDs must be different");
        }
        try {
            DefaultX509Source.X509SourceOptions options = DefaultX509Source.X509SourceOptions.builder()
                    .spiffeSocketPath(config.socket())
                    .initTimeout(config.initTimeout())
                    .build();
            this.source = DefaultX509Source.newSource(options);
            SpiffeId issuedId = source.getX509Svid().getSpiffeId();
            if (!ownId.equals(issuedId)) {
                source.close();
                throw new IllegalStateException(
                        "SPIRE issued " + issuedId + " but this workload requires " + ownId);
            }
            this.peerSslContext = SpiffeSslContextFactory.getSslContext(
                    SpiffeSslContextFactory.SslContextOptions.builder()
                            .sslProtocol("TLSv1.3")
                            .x509Source(source)
                            .acceptedSpiffeIdsSupplier(() -> Set.of(peerId))
                            .build());
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to initialize SPIFFE workload identity", exception);
        }
    }

    public DefaultX509Source source() {
        return source;
    }

    public SSLContext peerSslContext() {
        return peerSslContext;
    }

    @Override
    public void close() {
        source.close();
    }

    private static SpiffeId parse(String raw, String property) {
        try {
            return SpiffeId.parse(raw);
        } catch (RuntimeException exception) {
            throw new IllegalStateException("Invalid " + property, exception);
        }
    }

    private static void requireText(String value, String property) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(property + " must be configured when workload identity is enabled");
        }
    }
}
