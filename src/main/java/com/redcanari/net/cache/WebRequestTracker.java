package com.redcanari.net.cache;

import com.dlsc.trafficbrowser.beans.Traffic;
import com.redcanari.net.http.HttpRequest;
import com.redcanari.net.http.HttpResponse;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by ndouba on 14-11-20.
 */
public class WebRequestTracker {

    private static Map<URL, List<Traffic>> webRequests;
    private static WebRequestTracker instance = null;

    public static WebRequestTracker getInstance() {
        if (instance == null)
            instance = new WebRequestTracker();
        return instance;
    }

    private WebRequestTracker() {
        webRequests = new HashMap<>();
    }

    public void startRequest(URL url, HttpRequest httpRequest) {

    }

    public void endRequest(URL url, HttpResponse httpResponse) {

    }

}
