package com.kerosene.common.security.workload;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public final class InternalServiceAuthenticationFilter extends OncePerRequestFilter {

    public static final String CLIENT_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
    private static final int URI_SAN = 6;

    private final WorkloadIdentityConfig config;
    private final String legacySecret;
    private final List<String> protectedRoutes;

    public InternalServiceAuthenticationFilter(
            WorkloadIdentityConfig config,
            String legacySecret,
            List<String> protectedRoutes) {
        this.config = config;
        this.legacySecret = legacySecret;
        this.protectedRoutes = protectedRoutes.stream()
                .map(InternalServiceAuthenticationFilter::normalizeRoute)
                .toList();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return protectedRoutes.stream().noneMatch(
                route -> path.equals(route) || path.startsWith(route + "/"));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        if (config.enabled()) {
            if (!request.isSecure() || request.getLocalPort() != config.internalPort()) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            X509Certificate certificate = clientCertificate(request);
            if (certificate == null || !hasExactUriSan(certificate, config.peerSpiffeId())) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        } else {
            String credential = request.getHeader(InternalServiceRestTemplateFactory.LEGACY_HEADER);
            if (legacySecret == null || legacySecret.isBlank()) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                return;
            }
            if (credential == null || !constantTimeEquals(legacySecret, credential)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private static X509Certificate clientCertificate(HttpServletRequest request) {
        Object value = request.getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE);
        if (!(value instanceof X509Certificate[] certificates) || certificates.length == 0) {
            return null;
        }
        return certificates[0];
    }

    public static boolean hasExactUriSan(X509Certificate certificate, String expectedSpiffeId) {
        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans == null) {
                return false;
            }
            String found = null;
            for (List<?> san : sans) {
                if (san != null && san.size() >= 2 && Integer.valueOf(URI_SAN).equals(san.get(0))) {
                    if (found != null || !(san.get(1) instanceof String value)) {
                        return false;
                    }
                    found = value;
                }
            }
            return expectedSpiffeId != null && expectedSpiffeId.equals(found);
        } catch (CertificateParsingException exception) {
            return false;
        }
    }

    private static boolean constantTimeEquals(String expected, String provided) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
    }

    private static String normalizeRoute(String route) {
        if (route == null || route.isBlank() || !route.startsWith("/")) {
            throw new IllegalArgumentException("protected route must be an absolute application path");
        }
        return route.length() > 1 && route.endsWith("/")
                ? route.substring(0, route.length() - 1)
                : route;
    }
}
