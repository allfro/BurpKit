package com.redcanari.js.proxies;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import netscape.javascript.JSObject;

import java.util.List;

/**
 * Created by ndouba on 14-12-09.
 */
public class ScannerCheckJSProxy extends JSProxy implements IScannerCheck {

    public ScannerCheckJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
