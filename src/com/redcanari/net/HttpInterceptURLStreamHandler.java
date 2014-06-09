package com.redcanari.net;

import sun.net.www.protocol.https.HttpsURLConnectionImpl;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * Created by ndouba on 2014-06-01.
 */
public class HttpInterceptURLStreamHandler extends URLStreamHandler {

    @Override
    protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        return new InterceptedHttpURLConnection(url, proxy);
    }

    @Override
    protected URLConnection openConnection(URL url) throws IOException {
        return openConnection(url, null);
    }

}




