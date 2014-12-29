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

    public HttpMockResponse get(URL key) {
        return super.get(HttpUtils.normalizeUrl(key));
    }

    public HttpMockResponse put(URL key, HttpMockResponse value) {
        return super.put(HttpUtils.normalizeUrl(key), value);
    }

    public boolean containsKey(URL key) {
        return super.containsKey(HttpUtils.normalizeUrl(key));
    }
}
