package com.redcanari.js.proxies;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class MessageEditorTabFactoryJSProxy extends JSProxy implements IMessageEditorTabFactory{

    public MessageEditorTabFactoryJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return null;
    }
}
