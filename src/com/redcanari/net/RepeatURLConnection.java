package com.redcanari.net;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * Created by ndouba on 2014-06-01.
 */
@Deprecated
public class RepeatURLConnection extends URLConnection {

    private ByteArrayInputStream inputStream;

    public RepeatURLConnection(URL url) {
        super(url);
    }

    @Override
    synchronized public void connect() throws IOException {
        inputStream = new ByteArrayInputStream(
                ("<html><head><script>window.location=decodeURIComponent('http://www.google.ca')</script></head>" +
                "<body>Please wait while we redirect you to your final destination...</body></html>").getBytes()
        );
        connected = true;
    }

    @Override
    synchronized public InputStream getInputStream() throws IOException {
        if (!connected)
            connect();
        return inputStream;
    }
}
