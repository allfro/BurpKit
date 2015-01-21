package com.redcanari.js.proxies;

import burp.IHttpListener;
import burp.IHttpRequestResponse;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-08.
 */
public class HttpListenerJSProxy extends JSProxy implements IHttpListener {

    public HttpListenerJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        call("processHttpMessage", toolFlag, messageIsRequest, messageInfo);
    }
}
