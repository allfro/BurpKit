/*
 * BurpKit - WebKit-based penetration testing plugin for BurpSuite
 * Copyright (C) 2015  Red Canari, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.redcanari.burp;

import burp.*;
import com.redcanari.db.HttpMockResponseSQLCache;
import com.redcanari.net.http.HttpMockResponse;
import com.redcanari.ui.WebKitBrowser;
import com.redcanari.util.DigestUtils;
import com.redcanari.util.HttpUtils;

import java.awt.*;
import java.net.URL;

/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since   2014-06-01
 */
public class WebKitBrowserTab implements IMessageEditorTab
{
    private final WebKitBrowser webkitBrowser;
    private final IMessageEditorController controller;
    private final IExtensionHelpers helpers;
    private final HttpMockResponseSQLCache httpMockResponseCache;
    private byte[] currentResponse;

    public static final String REPEATER_PARAM_NAME = "Repeat; ";

    public WebKitBrowserTab(BurpExtender burpExtender, IMessageEditorController controller, boolean editable)
    {
        this.controller = controller;
        helpers = burpExtender.getHelpers();
        httpMockResponseCache = HttpMockResponseSQLCache.getInstance();
        webkitBrowser = new WebKitBrowser(controller);
    }

    // implement IMessageEditorTab

    @Override
    public String getTabCaption()
    {
        return "BurpKit";
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

    /*
     * Caches original response and issues mock request.
     *
     * Caches the original response in the {@link com.redcanari.net.cache.HttpMockResponseCache} singleton map and
     * issues the request via WebKit with a " (Repeater; <digest>)" string appended to the end of the User-Agent HTTP
     * header. The digest is used to differentiate between repeated requests and regular requests in the Java request
     * processing core.
     *
     * @param requestContent    the byte array containing the data for the request
     * @param responseContent   the byte array containing the data from the original response
     */
    private void cacheResponseAndFakeRequest(byte[] requestContent, byte[] responseContent) {

        IRequestInfo requestInfo = helpers.analyzeRequest(controller.getHttpService(), requestContent);

        // Save response for fake request using the URL and the digest of the request content. The digest is used to
        // differentiate between repeated requests that have different bodies of data since the mock request is fetched
        // using the HTTP GET method.
        URL url = requestInfo.getUrl();
        String digest = DigestUtils.toDigest(requestContent);
        httpMockResponseCache.put(
                digest,
                url,
                new HttpMockResponse(helpers.analyzeResponse(responseContent), responseContent)
        );

        // Issue mock request with modified User-Agent header.
        webkitBrowser.loadUrl(HttpUtils.normalizeUrl(url), " (" + REPEATER_PARAM_NAME + digest + ")");
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content != null)
            cacheResponseAndFakeRequest(controller.getRequest(), content);
    }

    @Override
    public byte[] getMessage()
    {
        // TODO: @see #isModified()
        return currentResponse;
    }

    @Override
    public boolean isModified()
    {
        // TODO: Maybe in the future we'll support before and after DOM comparisons and return the modified DOM as HTML.
        return false;
    }

    @Override
    public byte[] getSelectedData()
    {
        // TODO: return selected HTML when highlighting regions of the page using the mouse.
        return new byte[]{};
    }

}
