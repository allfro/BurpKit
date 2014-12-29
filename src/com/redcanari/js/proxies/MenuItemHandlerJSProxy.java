package com.redcanari.js.proxies;

import burp.IHttpRequestResponse;
import burp.IMenuItemHandler;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class MenuItemHandlerJSProxy extends JSProxy implements IMenuItemHandler {

    public MenuItemHandlerJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        call("menuItemClicked", menuItemCaption, messageInfo);
    }
}
