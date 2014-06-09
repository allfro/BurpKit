package com.redcanari.net.security;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * DO NOT USE IN PRODUCTION!!!!
 *
 * This class will simply trust everything that comes along.
 *
 * @author frank
 *
 */
public class TrustManager implements X509TrustManager {
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                                   String authType) {
    }

    public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                                   String authType) {
    }

}