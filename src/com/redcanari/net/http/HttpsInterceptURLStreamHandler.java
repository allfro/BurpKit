package com.redcanari.net.http;

import sun.net.www.protocol.https.Handler;
import sun.net.www.protocol.https.HttpsURLConnectionImpl;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
* Created by ndouba on 2014-06-04.
*/
public class HttpsInterceptURLStreamHandler extends Handler {

//    @Override
//    protected URLConnection openConnection(URL url) throws IOException {
//        return openConnection(url, null);
//    }

    @Override
    protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        return new InterceptedHttpsURLConnection(url, (HttpsURLConnectionImpl)super.openConnection(url, proxy));
    }
}
