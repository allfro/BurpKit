package com.redcanari.js.proxies;

import burp.IExtensionStateListener;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class ExtensionStateListenerJSProxy extends JSProxy implements IExtensionStateListener {

    public ExtensionStateListenerJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public void extensionUnloaded() {
        call("extensionUnloaded");
    }
}
