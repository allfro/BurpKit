package com.redcanari.net.cache;

import com.redcanari.net.CachedHttpResponse;
import com.redcanari.util.HttpUtils;

import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ndouba on 2014-06-01.
 */
public class HttpResponseCache extends ConcurrentHashMap<String, CachedHttpResponse> {

    private static HttpResponseCache instance = null;

    protected HttpResponseCache() {
        super();
    }

    public static HttpResponseCache getInstance() {
        if (instance == null)
            instance = new HttpResponseCache();
        return instance;
    }

    public CachedHttpResponse get(URL key) {
        return super.get(HttpUtils.normalizeUrl(key));
    }

    public CachedHttpResponse put(URL key, CachedHttpResponse value) {
        return super.put(HttpUtils.normalizeUrl(key), value);
    }

    public boolean containsKey(URL key) {
        return super.containsKey(HttpUtils.normalizeUrl(key));
    }
}
