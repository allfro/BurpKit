package com.redcanari.tainter;

import com.redcanari.util.HttpUtils;

import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ndouba on 2014-06-03.
 */
public class Tainter extends ConcurrentHashMap<String, String> {

    private static Integer lastId = -1;
    private static Tainter theTainter = new Tainter();

    protected Tainter() {
    }

    public static Tainter getInstance() {
        return theTainter;
    }

    public synchronized static String nextId() {
        Tainter.lastId++;
        return "tainter-" + Tainter.lastId;
    }

    public String put(String key, URL url) {
        return put(key, HttpUtils.normalizeUrl(url));
    }
}
