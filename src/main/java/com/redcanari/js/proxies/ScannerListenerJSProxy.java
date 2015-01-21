package com.redcanari.js.proxies;

import burp.IScanIssue;
import burp.IScannerListener;
import com.sun.glass.ui.Application;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class ScannerListenerJSProxy extends JSProxy implements IScannerListener {

    public ScannerListenerJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        call("newScanIssue", issue);
    }
}
