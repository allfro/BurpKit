package com.redcanari.burp;

import burp.*;
import com.redcanari.net.CachedHttpResponse;
import com.redcanari.net.cache.HttpResponseCache;
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
    private HttpResponseCache httpResponseCache;

    public static final String REPEATER_PARAM_NAME = "__repeater_id__";

    public WebKitBrowserTab(BurpExtender burpExtender, IMessageEditorController controller, boolean editable)
    {
        this.burpExtender = burpExtender;
        this.controller = controller;
        helpers = burpExtender.getHelpers();
        httpResponseCache = HttpResponseCache.getInstance();
        // create an instance of Burp's text editor, to display our deserialized data
        webkitBrowser = new WebKitBrowser();
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
        return !isRequest;
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
        httpResponseCache.put(
                url,
                new CachedHttpResponse(helpers.analyzeResponse(responseContent), responseContent)
        );

        // Go to fake URL
        webkitBrowser.loadUrl(HttpUtils.normalizeUrl(url));
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
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
