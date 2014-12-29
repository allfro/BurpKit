package com.redcanari.net.http;

import java.net.HttpURLConnection;

import java.util.*;

/**
 * Created by ndouba on 14-11-20.
 */

public class HttpMessage {

    private byte[] body;
    private Map<String, List<String>> headers;

    public HttpMessage(HttpURLConnection httpURLConnection) {
        headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
        parseHeaders(httpURLConnection.getRequestProperties());
    }

    private void parseHeaders(Map<String, List<String>> headerList) {
        headers.putAll(headerList);
    }

    public void addHeader(String name, String value) {
        List<String> values = getHeader(name);
        values.add(value);
    }

    public void removeHeader(String name) {
        if (headers.containsKey(name))
            headers.remove(name);
    }

    public void replaceHeader(String name, String value) {
        List<String> values = getHeader(name);
        if (!value.isEmpty())
            values.clear();
        values.add(value);
    }

    public List<String> getHeader(String name) {
        List<String> l = null;
        if (!headers.containsKey(name)) {
            l = new ArrayList<String>();
            headers.put(name, l);
        }
        else
            l = headers.get(name);
        return l;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

}

