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

package com.redcanari.net.cache;

import com.redcanari.net.http.HttpMockResponse;
import com.redcanari.util.HttpUtils;

import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ndouba on 2014-06-01.
 */
public class HttpMockResponseCache extends ConcurrentHashMap<String, HttpMockResponse> {

    private static HttpMockResponseCache instance = null;

    protected HttpMockResponseCache() {
        super();
    }

    public static HttpMockResponseCache getInstance() {
        if (instance == null)
            instance = new HttpMockResponseCache();
        return instance;
    }

    private String getKey(String digest, URL url) {
        return digest + ":" + HttpUtils.normalizeUrl(url);
    }

    public HttpMockResponse get(String digest, URL url) {
        String key = getKey(digest, url);
        HttpMockResponse object = super.get(getKey(digest, url));
        if (object != null)
            super.remove(getKey(digest, url));
        return object;
    }

    public HttpMockResponse put(String digest, URL url, HttpMockResponse value) {
        return super.put(getKey(digest, url), value);
    }

    public boolean containsKey(String digest, URL url) {
        return super.containsKey(getKey(digest, url));
    }
}
