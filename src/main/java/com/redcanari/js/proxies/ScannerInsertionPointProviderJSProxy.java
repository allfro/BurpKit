package com.redcanari.js.proxies;

import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import netscape.javascript.JSObject;

import java.util.List;

/**
 * Created by ndouba on 14-12-09.
 */
public class ScannerInsertionPointProviderJSProxy extends JSProxy implements IScannerInsertionPointProvider{

    public ScannerInsertionPointProviderJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        return null;
    }
}
