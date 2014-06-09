package com.redcanari.net;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

/**
 * Created by ndouba on 2014-06-01.
 */
public class HttpInterceptUrlStreamHandlerFactory implements URLStreamHandlerFactory {

//    public static final String REPEAT_PROTOCOL = "repeat";

    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        if (protocol.equalsIgnoreCase("https"))
            return new HttpsInterceptURLStreamHandler();
        else if (protocol.equalsIgnoreCase("http"))
            return new HttpInterceptURLStreamHandler();
        return null;
    }
}
