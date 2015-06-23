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

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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

