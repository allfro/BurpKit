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

import burp.IResponseInfo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.util.*;

/**
 * Created by ndouba on 2014-06-02.
 */
public class HttpMockResponse implements Serializable {

    private short statusCode;
    private byte[] body;
    private Map<String, List<String>> headers;
    private String inferredMimeType;
    private String statedMimeType;

    public HttpMockResponse(IResponseInfo responseInfo, byte[] content) {
        this.body = Arrays.copyOfRange(content, responseInfo.getBodyOffset(), content.length);
        headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        inferredMimeType = responseInfo.getInferredMimeType();
        statedMimeType = responseInfo.getStatedMimeType();
        statusCode = responseInfo.getStatusCode();
        parseHeaders(responseInfo.getHeaders());
    }

    private void parseHeaders(List<String> headerList) {
        headerList.remove(0);

        for (String header : headerList) {
            String[] keyValue = header.split("\\s*:\\s*", 2);
            addHeader(keyValue[0], keyValue[1]);
        }

        // Disable caching for intercepted requests.
        replaceHeader("Pragma", "no-cache");
        replaceHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        replaceHeader("Expires", "0");

        // Disable the built-in anti-XSS filter.
        replaceHeader("X-XSS-Protection", "0");
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

    public InputStream getInputStream() {
        return new ByteArrayInputStream(body);
    }

    public String getInferredMimeType() {
        return inferredMimeType;
    }

    public String getStatedMimeType() {
        return statedMimeType;
    }

    public short getStatusCode() {
        return statusCode;
    }
}
