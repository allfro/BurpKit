package com.redcanari.js.proxies;

import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class ProxyListenerJSProxy extends JSProxy implements IProxyListener  {

    public ProxyListenerJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public void processProxyMessage(boolean isRequest, IInterceptedProxyMessage interceptedProxyMessage) {
        call("processProxyMessage", isRequest, interceptedProxyMessage);
    }
}
