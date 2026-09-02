package com.kerosene.common.security.workload;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InternalServiceAuthenticationFilterTest {

    private static final String PEER_ID = "spiffe://staging.kerosene.internal/service/kfe";

    @Test
    void legacyModeFailsClosedWithoutSecret() throws Exception {
        InternalServiceAuthenticationFilter filter = filter(config(false), "");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request(), response, new MockFilterChain());

        assertEquals(503, response.getStatus());
    }

    @Test
    void legacyModeAcceptsOnlyMatchingHeader() throws Exception {
        InternalServiceAuthenticationFilter filter = filter(config(false), "credential");
        MockHttpServletRequest request = request();
        request.addHeader(InternalServiceRestTemplateFactory.LEGACY_HEADER, "credential");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
    }

    @Test
    void protectsExactRouteButNotSimilarPublicRoute() throws Exception {
        InternalServiceAuthenticationFilter filter = filter(config(false), "credential");
        MockHttpServletResponse exactResponse = new MockHttpServletResponse();
        MockHttpServletResponse similarResponse = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("GET", "/internal"), exactResponse, new MockFilterChain());
        filter.doFilter(new MockHttpServletRequest("GET", "/internal-public"), similarResponse, new MockFilterChain());

        assertEquals(401, exactResponse.getStatus());
        assertEquals(200, similarResponse.getStatus());
    }

    @Test
    void mtlsModeRejectsPublicConnectorEvenWithLegacyHeader() throws Exception {
        InternalServiceAuthenticationFilter filter = filter(config(true), "credential");
        MockHttpServletRequest request = request();
        request.addHeader(InternalServiceRestTemplateFactory.LEGACY_HEADER, "credential");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }

    @Test
    void mtlsModeAcceptsExactSingleUriSan() throws Exception {
        InternalServiceAuthenticationFilter filter = filter(config(true), "");
        MockHttpServletRequest request = secureRequest(certificate(List.of(List.of(6, PEER_ID))));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
    }

    @Test
    void mtlsModeRejectsAmbiguousUriSan() throws Exception {
        InternalServiceAuthenticationFilter filter = filter(config(true), "");
        MockHttpServletRequest request = secureRequest(certificate(List.of(
                List.of(6, PEER_ID),
                List.of(6, "spiffe://staging.kerosene.internal/service/node"))));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }

    private static InternalServiceAuthenticationFilter filter(WorkloadIdentityConfig config, String secret) {
        return new InternalServiceAuthenticationFilter(config, secret, List.of("/internal/"));
    }

    private static WorkloadIdentityConfig config(boolean enabled) {
        return new WorkloadIdentityConfig(
                enabled,
                "unix:///run/spire.sock",
                "spiffe://staging.kerosene.internal/service/auth",
                PEER_ID,
                8443,
                Duration.ofSeconds(1));
    }

    private static MockHttpServletRequest request() {
        return new MockHttpServletRequest("POST", "/internal/test");
    }

    private static MockHttpServletRequest secureRequest(X509Certificate certificate) {
        MockHttpServletRequest request = request();
        request.setSecure(true);
        request.setLocalPort(8443);
        request.setAttribute(
                InternalServiceAuthenticationFilter.CLIENT_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{certificate});
        return request;
    }

    @SuppressWarnings("unchecked")
    private static X509Certificate certificate(List<List<?>> sans) throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectAlternativeNames()).thenReturn((List) sans);
        return certificate;
    }
}
