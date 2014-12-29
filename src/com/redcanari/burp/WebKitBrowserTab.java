package com.redcanari.burp;

import burp.*;
import com.redcanari.net.http.HttpMockResponse;
import com.redcanari.net.cache.HttpMockResponseCache;
import com.redcanari.ui.WebKitBrowser;
import com.redcanari.util.DigestUtils;
import com.redcanari.util.HttpUtils;

import java.awt.*;
import java.net.URL;

/**
* Created by ndouba on 2014-06-01.
*/
public class WebKitBrowserTab implements IMessageEditorTab
{
    private BurpExtender burpExtender;
    private WebKitBrowser webkitBrowser;
    private IMessageEditorController controller;
    private IExtensionHelpers helpers;
    private byte[] currentResponse;
    private HttpMockResponseCache httpMockResponseCache;

    public static final String REPEATER_PARAM_NAME = "__repeater_id__";

    public WebKitBrowserTab(BurpExtender burpExtender, IMessageEditorController controller, boolean editable)
    {
//        System.out.println("Initialized new tab");
        this.burpExtender = burpExtender;
        this.controller = controller;
        helpers = burpExtender.getHelpers();
        httpMockResponseCache = HttpMockResponseCache.getInstance();
        webkitBrowser = new WebKitBrowser(controller);
    }

    //
    // implement IMessageEditorTab
    //

    @Override
    public String getTabCaption()
    {
        return "Webkit Render";
    }

    @Override
    public Component getUiComponent()
    {
        return webkitBrowser;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
        return !isRequest && helpers.analyzeResponse(content).getInferredMimeType().equals("HTML");
    }

    private void cacheResponseAndFakeRequest(byte[] requestContent, byte[] responseContent) {
        // First build a tracking parameter
        IParameter parameter = helpers.buildParameter(
                REPEATER_PARAM_NAME,
                DigestUtils.toDigest(requestContent),
                IParameter.PARAM_URL
        );

        requestContent = helpers.addParameter(requestContent, parameter);
        IRequestInfo requestInfo = helpers.analyzeRequest(controller.getHttpService(), requestContent);

        // Save response for fake request
        URL url = requestInfo.getUrl();
        httpMockResponseCache.put(
                url,
                new HttpMockResponse(helpers.analyzeResponse(responseContent), responseContent)
        );

        // Go to fake URL
        webkitBrowser.loadUrl(HttpUtils.normalizeUrl(url));
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content != null)
            cacheResponseAndFakeRequest(controller.getRequest(), content);
    }

    @Override
    public byte[] getMessage()
    {
        return currentResponse;
    }

    @Override
    public boolean isModified()
    {
        return false;
    }

    @Override
    public byte[] getSelectedData()
    {
        return new byte[]{};
    }




}
