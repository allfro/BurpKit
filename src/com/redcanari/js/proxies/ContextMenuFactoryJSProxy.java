package com.redcanari.js.proxies;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import netscape.javascript.JSObject;

import javax.swing.*;
import java.util.List;

/**
 * Created by ndouba on 14-12-09.
 */
public class ContextMenuFactoryJSProxy extends JSProxy implements IContextMenuFactory {

    public ContextMenuFactoryJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return null;
    }

}
