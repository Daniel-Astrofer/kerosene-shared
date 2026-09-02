package com.kerosene.common.security.workload;

import org.springframework.http.client.SimpleClientHttpRequestFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.HttpURLConnection;

final class SpiffeClientHttpRequestFactory extends SimpleClientHttpRequestFactory {

    private final SSLContext sslContext;

    SpiffeClientHttpRequestFactory(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    @Override
    protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
        super.prepareConnection(connection, httpMethod);
        if (!(connection instanceof HttpsURLConnection https)) {
            throw new IOException("SPIFFE internal client refuses clear-text HTTP");
        }
        https.setSSLSocketFactory(sslContext.getSocketFactory());
        // SpiffeTrustManager pins the exact URI SAN. DNS hostname verification is
        // intentionally inapplicable to an X.509-SVID without a DNS SAN.
        https.setHostnameVerifier((hostname, session) -> true);
    }
}
