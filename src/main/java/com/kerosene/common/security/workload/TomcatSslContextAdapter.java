package com.kerosene.common.security.workload;

import io.spiffe.workloadapi.X509Source;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public final class TomcatSslContextAdapter implements org.apache.tomcat.util.net.SSLContext {

    private final javax.net.ssl.SSLContext delegate;
    private final X509Source source;

    public TomcatSslContextAdapter(javax.net.ssl.SSLContext delegate, X509Source source) {
        this.delegate = delegate;
        this.source = source;
    }

    @Override
    public void init(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) {
        // The SPIFFE-backed JSSE context is initialized before Tomcat receives it.
    }

    @Override
    public void destroy() {
        // The application bean owns the streaming Workload API source.
    }

    @Override
    public SSLSessionContext getServerSessionContext() {
        return delegate.getServerSessionContext();
    }

    @Override
    public SSLEngine createSSLEngine() {
        return delegate.createSSLEngine();
    }

    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        return delegate.getServerSocketFactory();
    }

    @Override
    public SSLParameters getSupportedSSLParameters() {
        return delegate.getSupportedSSLParameters();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return source.getX509Svid().getChainArray();
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
