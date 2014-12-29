package com.redcanari.js.proxies;

import burp.IHttpService;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class HttpServiceJSProxy extends JSProxy implements IHttpService{

    public HttpServiceJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getHost() {
        return (String) call("getHost");
    }

    @Override
    public int getPort() {
        return (int) call("getPort");
    }

    @Override
    public String getProtocol() {
        return (String) call("getProtocol");
    }
}
