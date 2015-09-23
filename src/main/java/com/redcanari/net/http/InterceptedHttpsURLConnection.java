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

package com.redcanari.net.http;


import com.redcanari.burp.WebKitBrowserTab;
import com.redcanari.db.HttpMockResponseSQLCache;
import sun.net.www.protocol.https.DelegateHttpsURLConnection;
import sun.net.www.protocol.https.HttpsURLConnectionImpl;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Created by ndouba on 2014-06-01.
 */
public class InterceptedHttpsURLConnection extends HttpsURLConnectionImpl {

    private HttpMockResponseSQLCache httpMockResponseCache;
    private boolean isIntercepted = false;
    private HttpMockResponse httpMockResponse = null;
    private InputStream inputStream;

    private final Pattern pattern = Pattern.compile(WebKitBrowserTab.REPEATER_PARAM_NAME + "([a-zA-Z0-9]+)\\)");



    public InterceptedHttpsURLConnection(URL url, HttpsURLConnectionImpl impl) throws IOException {
        super(url);

        try {
            Field f = null;
            f = impl.getClass().getDeclaredField("delegate");
            f.setAccessible(true);
            delegate = (DelegateHttpsURLConnection)f.get(impl);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
        setUseCaches(false);
        setDefaultUseCaches(false);
        httpMockResponseCache = HttpMockResponseSQLCache.getInstance();
    }

    @Override
    synchronized public void connect() throws IOException {
//        System.err.println("Processing request: " + url + ", Request Headers: " + super.getRequestProperties());
        String digest = getRepeaterDigest();
        if (digest != null && httpMockResponseCache.containsKey(digest, url)) {
//            System.err.println("Intercepting request: " + url);

            isIntercepted = true;
            httpMockResponse = httpMockResponseCache.get(digest, url);
            responseCode = httpMockResponse.getStatusCode();

            try {
                delegate.getCookieHandler().put(getURL().toURI(), getHeaderFields());
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
            inputStream = httpMockResponse.getInputStream();
            setConnected(true);
        } else
            super.connect();
    }

    /**
     * Returns the message digest contained in the User-Agent HTTP header.
     *
     * Extracts and returns the message digest contained in the User-Agent HTTP header, if present. Otherwise,
     * {@value null} is returned, indicating that the request is not a repeated one.
     *
     * @return  a string containing the message digest or {@value null} if no message digest exists.
     */
    private synchronized String getRepeaterDigest() {
        String userAgent = getRequestProperty("User-Agent");
        if (userAgent == null)
            return null;
        Matcher matcher = pattern.matcher(userAgent);
        if (!matcher.find())
            return null;
        return matcher.group(1);
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
            return httpMockResponse.getHeaders();
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


//    @Override
//    public void addWebRequestListener(URL scope, ObservableList<Traffic> observer) {
//
//    }
//
//    @Override
//    public void removeWebRequestListener(URL scope) {
//
//    }
}
