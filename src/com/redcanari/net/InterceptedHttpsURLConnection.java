package com.redcanari.net;


import com.redcanari.burp.WebKitBrowserTab;
import com.redcanari.net.cache.HttpResponseCache;
import sun.net.www.protocol.https.DelegateHttpsURLConnection;
import sun.net.www.protocol.https.HttpsURLConnectionImpl;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;



/**
 * Created by ndouba on 2014-06-01.
 */
public class InterceptedHttpsURLConnection extends HttpsURLConnectionImpl {

    private HttpResponseCache httpResponseCache;
    private boolean isIntercepted = false;
    private CachedHttpResponse cachedHttpResponse = null;
    private InputStream inputStream;


    public InterceptedHttpsURLConnection(URL url, HttpsURLConnectionImpl impl) throws IOException {
        super(url);
        try {
            Field f = null;
            f = impl.getClass().getDeclaredField("delegate");
            f.setAccessible(true);
            delegate = (DelegateHttpsURLConnection)f.get(impl);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        setUseCaches(false);
        setDefaultUseCaches(false);
        httpResponseCache = HttpResponseCache.getInstance();

    }

    @Override
    synchronized public void connect() throws IOException {
        System.err.println("Processing request: " + url);
        if (url.getFile().contains(WebKitBrowserTab.REPEATER_PARAM_NAME) && httpResponseCache.containsKey(url)) {
            System.err.println("Intercepting request: " + url);

            isIntercepted = true;
            cachedHttpResponse = httpResponseCache.get(url);
            responseCode = cachedHttpResponse.getStatusCode();

            try {
                delegate.getCookieHandler().put(getURL().toURI(), getHeaderFields());
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
            inputStream = cachedHttpResponse.getInputStream();
            setConnected(true);
        } else
            super.connect();
    }

    @Override
    public int getResponseCode() throws IOException {
        if (isIntercepted)
            return responseCode;
        return super.getResponseCode();
    }

    @Override
    public String getHeaderField(String name) {
        if (isIntercepted) {
            List<String> headers = getHeaderFields().get(name);
            if (headers != null && !headers.isEmpty())
                return headers.get(0);
            return null;
        }
        return super.getHeaderField(name);
    }

    @Override
    public String getContentType() {
        return getHeaderField("content-type");
    }

    public String getContentEncoding() {
        return getHeaderField("content-encoding");
    }

    @Override
    synchronized public Map<String, List<String>> getHeaderFields() {
        if (isIntercepted)
            return cachedHttpResponse.getHeaders();
        return super.getHeaderFields();
    }

    @Override
    synchronized public InputStream getInputStream() throws IOException {
        if (!isConnected())
            connect();
        if (isIntercepted)
            return inputStream;
        return super.getInputStream();
    }


}
