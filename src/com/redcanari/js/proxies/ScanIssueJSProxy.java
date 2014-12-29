package com.redcanari.js.proxies;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import com.redcanari.js.Helpers;
import netscape.javascript.JSObject;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created by ndouba on 14-12-09.
 */
public class ScanIssueJSProxy extends JSProxy implements IScanIssue {

    public ScanIssueJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public URL getUrl() {
        try {
            return new URL((String)call("getURL"));
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public String getIssueName() {
        return (String) call("getIssueName");
    }

    @Override
    public int getIssueType() {
        return (int) call("getIssueType");
    }

    @Override
    public String getSeverity() {
        return (String) call("getSeverity");
    }

    @Override
    public String getConfidence() {
        return (String) call("getConfidence");
    }

    @Override
    public String getIssueBackground() {
        return (String) call("getIssueBackground");
    }

    @Override
    public String getRemediationBackground() {
        return (String) call("getRemediationBackground");
    }

    @Override
    public String getIssueDetail() {
        return (String) call("getIssueDetail");
    }

    @Override
    public String getRemediationDetail() {
        return (String) call("getRemediationDetail");
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return (IHttpRequestResponse[]) Helpers.toJavaArray((JSObject) call("getHttpMessages"), IHttpRequestResponse.class);
    }

    @Override
    public IHttpService getHttpService() {
        Object httpService = call("getHttpService");
        if (httpService instanceof JSObject)
            httpService = new HttpServiceJSProxy((JSObject) httpService);
        return (IHttpService) httpService;
    }

    @Override
    public String getHost() {
        return (String) call("getHost");
    }

    @Override
    public int getPort() {
        return (int) call("getPort");
    }

    @Override
    public String getProtocol() {
        return (String) call("getProtocol");
    }
}
