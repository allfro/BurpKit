package burp;

import com.redcanari.burp.WebKitBrowserTab;
import com.redcanari.net.http.HttpInterceptUrlStreamHandlerFactory;
import com.redcanari.net.security.TrustManager;
import com.redcanari.tainter.Tainter;
import com.redcanari.ui.WebKitBrowser;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IProxyListener, ITab {
    private static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Tainter tainter;
    private final WebKitBrowser webKitBrowser = new WebKitBrowser(true);
    private WebKitBrowserTab webKitBrowserTab = null;

    //
    // implement IBurpExtender
    //

    public static IBurpExtenderCallbacks getBurpExtenderCallbacks() {
        return BurpExtender.callbacks;
    }
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        BurpExtender.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Webkit Renderer");
        
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        callbacks.registerContextMenuFactory(this);
        callbacks.registerProxyListener(this);

        callbacks.addSuiteTab(this);

        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[] { new TrustManager() }, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String string, SSLSession ssls) {
                    return true;
                }
            });
//            System.setProperty("https.proxyHost", "localhost");
//            System.setProperty("https.proxyPort", "8080");
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        try {
            URL.setURLStreamHandlerFactory(new HttpInterceptUrlStreamHandlerFactory());
        }
        catch (Throwable ignored) {
            // Who cares if it's loaded multiple times ;)
        }


//        webKitBrowser = new WebKitBrowser();

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

    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocationContext) {
        if (invocationContext.getToolFlag() != IBurpExtenderCallbacks.TOOL_REPEATER)
            return null;

        if (invocationContext.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
            return null;

        List<JMenuItem> menuItemList = new ArrayList<JMenuItem>();
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

    @Override
    public void processProxyMessage(boolean isRequest, IInterceptedProxyMessage message) {
//        if (isRequest)
//            return;
//        if (helpers.analyzeResponse(message.getMessageInfo().getResponse()).getInferredMimeType().equals("HTML"))
//            webKitBrowser.loadUrl(message.getMessageInfo().getUrl().toString());
    }

    @Override
    public String getTabCaption() {
        return "WebKit Browser";
    }

    @Override
    public Component getUiComponent() {
        return webKitBrowser;
    }
}
