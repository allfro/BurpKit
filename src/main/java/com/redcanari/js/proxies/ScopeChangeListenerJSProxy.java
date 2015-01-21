package com.redcanari.js.proxies;

import burp.IScopeChangeListener;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class ScopeChangeListenerJSProxy extends JSProxy implements IScopeChangeListener {

    public ScopeChangeListenerJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public void scopeChanged() {
        call("scopeChanged");
    }
}
