package com.redcanari.js.proxies;

import burp.IHttpRequestResponse;
import burp.ISessionHandlingAction;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class SessionHandlingActionJSProxy extends JSProxy implements ISessionHandlingAction {

    public SessionHandlingActionJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getActionName() {
        return null;
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        call("performAction", currentRequest, macroItems);
    }
}
