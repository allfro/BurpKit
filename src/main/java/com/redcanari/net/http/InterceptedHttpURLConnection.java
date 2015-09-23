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
import sun.net.www.protocol.http.HttpURLConnection;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since   2014-06-01.
 */
public class InterceptedHttpURLConnection extends HttpURLConnection {

    private final HttpMockResponseSQLCache httpMockResponseCache;

    /**
     * Internal connection state variables used to support fake requests/responses.
     */
    private boolean isIntercepted = false;
    private HttpMockResponse httpMockResponse = null;
    private InputStream inputStream;

    /**
     * Used to extract the message digest from the User-Agent HTTP header.
     */
    private final Pattern pattern = Pattern.compile(WebKitBrowserTab.REPEATER_PARAM_NAME + "([a-zA-Z0-9]+)\\)");

    public InterceptedHttpURLConnection(URL url, Proxy proxy) {
        super(url, proxy);

        // Disable caching to guarantee response freshness
        setUseCaches(false);
        setDefaultUseCaches(false);

        // Get our instance of the HttpMockResponseCache map to detect repeated requests.
        httpMockResponseCache = HttpMockResponseSQLCache.getInstance();
    }

    public InterceptedHttpURLConnection(URL url) throws IOException {
        this(url, null);
    }

    @Override
    /**
     * Sets {@code #connected} to {@value false}.
     */
    public void disconnect() {
        connected = false;
    }

    @Override
    /**
     * Returns false because proxies are not supported yet.
     *
     * @returns {@value false}
     */
    public boolean usingProxy() {
        return false;
    }

    @Override
    /**
     * Connects to the target HTTP server and sets up internal connection state.
     *
     * Implemented to support the Repeater tab in BurpSuite and to fake a request and response void of reissuing the
     * original request. If the request contains a message digest and the URL can be found in the
     * {@code com.redcanari.net.cache.HttpMockResponseCache} map then all the necessary state variables are initialized
     * via the corresponding {@code com.redcanari.net.http.HttpMockResponse} object. Otherwise, control is handed over
     * to the super class and a live request is issued to the server.
     */
    synchronized public void connect() throws IOException {
//        System.err.println("Processing request: " + url + ", Request Headers: " + super.getRequestProperties());
        String digest = getRepeaterDigest();
        if (digest != null && httpMockResponseCache.containsKey(digest, url)) {
//            System.err.println("Intercepting request: " + url);

            isIntercepted = true;
            httpMockResponse = httpMockResponseCache.get(digest, url);
            responseCode = httpMockResponse.getStatusCode();

            try {
                getCookieHandler().put(getURL().toURI(), getHeaderFields());
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
            inputStream = httpMockResponse.getInputStream();
            connected = true;
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
    /**
     * Returns the response headers from the server or the {@code #httpMockResponse} field.
     *
     * Implemented to support the Repeater tab in BurpSuite and to return the original response headers void of
     * reissuing the original request. If the {@code #isIntercepted} field is {@value true} then the response headers
     * from the {@code #httpMockResponse} field are returned. Otherwise, a network request is issued and the headers
     * from the response are returned.
     *
     * @return  a map containing the response headers.
     */
    synchronized public Map<String, List<String>> getHeaderFields() {
        if (isIntercepted)
            return httpMockResponse.getHeaders();
        return super.getHeaderFields();
    }

    @Override
    /**
     * Returns an InputStream object either from {@code #httpMockResponse} or the super class.
     *
     * Implemented to support the Repeater tab in BurpSuite and to return the original response data void of
     * reissuing the original request. If the {@code #isIntercepted} field is {@value true} then the response data
     * from the {@code #inputStream} field is returned. Otherwise, a network request is issued and the data from the
     * corresponding response is returned as an {@code InputStream}.
     *
     * @return  an {@code InputStream} containing the response data.
     */
    synchronized public InputStream getInputStream() throws IOException {
        if (!connected)
            connect();
        if (isIntercepted)
            return inputStream;
        return super.getInputStream();
    }

}
