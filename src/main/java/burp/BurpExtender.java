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

package burp;

import com.redcanari.burp.JythonTab;
import com.redcanari.burp.WebKitBrowserTab;
import com.redcanari.net.http.HttpInterceptUrlStreamHandlerFactory;
import com.redcanari.net.security.TrustManager;
import com.redcanari.tainter.Tainter;
import com.redcanari.ui.WebKitBrowser;
import com.redcanari.ui.font.FontAwesome;
import com.redcanari.util.SSLUtilities;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since 2014-01-01
 */
public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, ITab {
    private static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Tainter tainter;
    private final WebKitBrowser webKitBrowser = new WebKitBrowser(true);

    //
    // implement IBurpExtender
    //


    /**
     * Checks if the version of the JVM is supported by BurpKit.
     *
     * @return true if supported, otherwise false
     */
    public boolean isRunningSupportedJVM() {
        String javaVersion = System.getProperty("java.version");

        String[] splitVersion = javaVersion.split("[._-]");
        int major = Integer.valueOf(splitVersion[0]);
        int minor = Integer.valueOf(splitVersion[1]);
        int revision = Integer.valueOf(splitVersion[2]);
        int update = Integer.valueOf(splitVersion[3]);

        return (major >= 1 && minor == 8 && revision >= 0 && update >= 31);
    }

    /**
     * Returns the instance of {@link burp.IBurpExtenderCallbacks} provided by the BurpSuite framework.
     *
     * @return an instance of {@link burp.IBurpExtenderCallbacks}
     */
    public static IBurpExtenderCallbacks getBurpExtenderCallbacks() {
        return BurpExtender.callbacks;
    }
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

        // Initialize FontAwesome font with size 14 font for JVM.
        FontAwesome.initialize(14);

        // Make sure we're running the correct version of Java with JavaFX.
        if (!isRunningSupportedJVM()) {
            callbacks.printError(
                    "The current version of Java/JFX you're running is currently not supported\n" +
                    "by this plugin. Please download at least 1.8.0u31-b31 from the Oracle website."
            );
            throw new RuntimeException();
        }
        // keep a reference to our callbacks object
        BurpExtender.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("BurpKit 1.02");
        
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        callbacks.registerContextMenuFactory(this);

//        callbacks.registerProxyListener(this);

        // Add the courtesy BurpKit browser as a top-level tab in BurpSuite.
        callbacks.addSuiteTab(this);
        callbacks.addSuiteTab(new BurpScriptTab());
        callbacks.addSuiteTab(new JythonTab());

        // Ignore invalid SSL certificates.
        SSLUtilities.trustAll();


        // Setup our request interceptor for the JVM
        try {
            URL.setURLStreamHandlerFactory(new HttpInterceptUrlStreamHandlerFactory());
        }
        catch (Throwable ignored) {
            // Who cares if it's loaded multiple times ;)
        }

        tainter = Tainter.getInstance();
    }

    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        return new WebKitBrowserTab(this, controller, editable);
    }

    /**
     * Returns the instance of {@link burp.IExtensionHelpers} provided by the BurpSuite framework.
     *
     * @return  an instance of {@link burp.IExtensionHelpers}
     */
    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocationContext) {
        if (invocationContext.getToolFlag() != IBurpExtenderCallbacks.TOOL_REPEATER)
            return null;

        if (invocationContext.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
            return null;

        List<JMenuItem> menuItemList = new ArrayList<>();
        JMenuItem menuItem = new JMenuItem("Taint");
        menuItem.addActionListener(e -> {
            int[] bounds = invocationContext.getSelectionBounds();
            IHttpRequestResponse message = invocationContext.getSelectedMessages()[0];
            String request = helpers.bytesToString(message.getRequest());

            String tainterId = Tainter.nextId();
            tainter.put(tainterId, message.getUrl());

            if (bounds[0] == bounds[1])
                request = new StringBuilder(request).insert(bounds[0], tainterId).toString();
            else {
                String selection = helpers.bytesToString(
                        Arrays.copyOfRange(message.getRequest(), bounds[0], bounds[1])
                );
                request = request.replace(selection, tainterId);
            }

            message.setRequest(helpers.stringToBytes(request));
        });
        menuItemList.add(menuItem);
        return menuItemList;

    }

//    @Override
//    public void processProxyMessage(boolean isRequest, IInterceptedProxyMessage message) {
//        if (isRequest)
//            return;
//        if (helpers.analyzeResponse(message.getMessageInfo().getResponse()).getInferredMimeType().equals("HTML"))
//            webKitBrowser.loadUrl(message.getMessageInfo().getUrl().toString());
//    }

    @Override
    public String getTabCaption() {
        return "BurpKitty";
    }

    @Override
    public Component getUiComponent() {
        return webKitBrowser;
    }
}
