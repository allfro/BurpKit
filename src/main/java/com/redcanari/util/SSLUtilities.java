/*
 * BurpKit - WebKit-based penetration testing plugin for BurpSuite
 * Copyright (C) 2015  Red Canari, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.redcanari.util;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * This class provide various static methods that relax X509 certificate and
 * hostname verification while using the SSL over the HTTP protocol.
 *
 * @author    Francis Labrie
 */
public final class SSLUtilities {

    private static final String[] protocols = new String[] {
            "SSL",
            "SSLv2",
            "SSLv3",
            "TLS",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2"
    };

    public static void trustAll() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager(){
            public X509Certificate[] getAcceptedIssuers(){return null;}
            public void checkClientTrusted(X509Certificate[] certs, String authType){}
            public void checkServerTrusted(X509Certificate[] certs, String authType){}
        }};

        // Install the all-trusting trust managers
//        for (String protocol: protocols) {
        try {
            SSLContext sc = SSLContext.getInstance(protocols[2]);
            sc.init(null, trustAllCerts, new SecureRandom());
            SSLContext.setDefault(sc);
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception ignored) {}
//        }

        HttpsURLConnection.setDefaultHostnameVerifier((s, sslSession) -> true);
    }

} // SSLUtilities