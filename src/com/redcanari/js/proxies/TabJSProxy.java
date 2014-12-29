package com.redcanari.js.proxies;

import burp.ITab;
import netscape.javascript.JSObject;

import java.awt.*;

/**
 * Created by ndouba on 14-12-09.
 */
public class TabJSProxy extends JSProxy implements ITab {

    public TabJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getTabCaption() {
        return (String) call("getTabCaption");
    }

    @Override
    public Component getUiComponent() {
        return (Component) call("getUiComponent");
    }

}
