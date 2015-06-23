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

package com.redcanari.js;

import burp.*;
import com.redcanari.js.proxies.*;
import com.redcanari.swing.SwingFXUtilities;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.CookieHandler;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author  Nadeem Douba
 * @version 1.0
 * @since   2014-11-16.
 */
@SuppressWarnings({"UnusedDeclaration", "unchecked"})
public class BurpExtenderCallbacksBridge extends JavaScriptBridge {

    public static final int TOOL_SUITE = 1;
    public static final int TOOL_TARGET = 2;
    public static final int TOOL_PROXY = 4;
    public static final int TOOL_SPIDER = 8;
    public static final int TOOL_SCANNER = 16;
    public static final int TOOL_INTRUDER = 32;
    public static final int TOOL_REPEATER = 64;
    public static final int TOOL_SEQUENCER = 128;
    public static final int TOOL_DECODER = 256;
    public static final int TOOL_COMPARER = 512;
    public static final int TOOL_EXTENDER = 1024;

    private final ExtensionHelpersBridge extensionHelpersBridge;

    public BurpExtenderCallbacksBridge(WebEngine webEngine, IBurpExtenderCallbacks burpExtenderCallbacks) {
        super(webEngine, burpExtenderCallbacks);
        extensionHelpersBridge = new ExtensionHelpersBridge(webEngine, burpExtenderCallbacks);
    }


    /**
     * Returns the string representation of the object in the JavaScript console.
     *
     * @return the string representation of this object.
     */
    public String toString() {
        return "[object BurpExtenderCallbacks]";
    }


    /**
     * A helper method that builds the body of an HTTP GET request with the cookies that are present in the JavaFX
     * cookie jar.
     *
     * @param url The URL of the request.
     * @return A {@code byte[]} containing the HTTP GET request and all its headers.
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     */
    protected byte[] buildHttpRequestWithCookies(URL url) throws URISyntaxException, IOException {
        byte[] body = helpers.buildHttpRequest(url);
        List<String> cookies = (List<String>) CookieHandler.getDefault().get(url.toURI(), Collections.EMPTY_MAP).get("Cookie");
        if (cookies != null && !cookies.isEmpty())
            body = new String(body).replace("\r\n\r\n", "\r\nCookie: " + String.join("; ", cookies) + "\r\n\r\n").getBytes();
        return body;
    }


    /**
     * This method is used to set the display name for the current extension, which will be displayed within the user
     * interface for the Extender tool.
     *
     * @param name The extension name.
     */
    public void setExtensionName(String name) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.setExtensionName(name));
//        try {
//            SwingUtilities.invokeAndWait(() -> burpExtenderCallbacks.setExtensionName(name));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//        }
    }


    /**
     * This method is used to obtain an IExtensionHelpers object, which can be used by the extension to perform numerous
     * useful tasks.
     *
     * @return An {@link burp.IExtensionHelpers} object that aids with tasks such as building and analyzing HTTP requests.
     */
    public ExtensionHelpersBridge getHelpers() {
        return extensionHelpersBridge;
    }


    /**
     * This method is used to obtain the current extension's standard output stream. Extensions should write all output
     * to this stream, allowing the Burp user to configure how that output is handled from within the UI.
     *
     * @return The extension's standard output stream.
     */
    public OutputStream getStdout() {
        return burpExtenderCallbacks.getStdout();
    }


    /**
     * This method is used to obtain the current extension's standard error stream. Extensions should write all error
     * messages to this stream, allowing the Burp user to configure how that output is handled from within the UI.
     *
     * @return The extension's standard error stream.
     */
    public OutputStream getStderr() {
        return burpExtenderCallbacks.getStderr();
    }


    /**
     * This method prints a line of output to the current extension's standard output stream.
     *
     * @param message The message to print.
     */
    public void printOutput(String message) {
//        try {
//            SwingUtilities.invokeAndWait(() -> burpExtenderCallbacks.printOutput(message));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//        }
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.printOutput(message));
    }


    /**
     * This method prints a line of output to the current extension's standard error stream.
     *
     * @param message The message to print.
     */
    public void printError(String message) {
//        try {
//            SwingUtilities.invokeAndWait(() -> burpExtenderCallbacks.printError(message));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//        }
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.printError(message));
    }


    /**
     * This method is used to register a listener which will be notified of changes to the extension's state. Note: Any
     * extensions that start background threads or open system resources (such as files or database connections) should
     * register a listener and terminate threads / close resources when the extension is unloaded.
     *
     * @param listener An object created by the extension that implements the {@link burp.IExtensionStateListener}
     *                 interface.
     * @return The instance of {@link burp.IExtensionStateListener} that was registered.
     */
    public IExtensionStateListener registerExtensionStateListener(Object listener) {
        final IExtensionStateListener l = Helpers.<IExtensionStateListener>wrapInterface(listener, ExtensionStateListenerJSProxy.class);
        SwingUtilities.invokeLater(
                () -> burpExtenderCallbacks.registerExtensionStateListener(l)
        );
        return l;
    }


    /**
     * This method is used to retrieve the extension state listeners that are registered by the extension.
     *
     * @return A list of extension state listeners that are currently registered by this extension.
     */
    public JSObject getExtensionStateListeners() {
//        List<IExtensionStateListener> listeners;
//        try {
//            listeners = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getExtensionStateListeners);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, listeners);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getExtensionStateListeners());
    }


    /**
     * This method is used to remove an extension state listener that has been registered by the extension.
     * @param listener The extension state listener to be removed.
     */
    public void removeExtensionStateListener(IExtensionStateListener listener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeExtensionStateListener(listener));
    }


    /**
     * This method is used to register a listener which will be notified of requests and responses made by any Burp tool.
     * Extensions can perform custom analysis or modification of these messages by registering an HTTP listener.
     *
     * @param listener An object created by the extension that implements the {@link burp.IHttpListener} interface.
     * @return The instance of {@link burp.IHttpListener} that was registered.
     */
    public IHttpListener registerHttpListener(Object listener) {
        final IHttpListener l = Helpers.<IHttpListener>wrapInterface(listener, HttpListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerHttpListener(l));
        return l;
    }


    /**
     * This method is used to retrieve the HTTP listeners that are registered by the extension.
     *
     * @return A list of HTTP listeners that are currently registered by this extension.
     */
    public JSObject getHttpListeners() {
//        List<IHttpListener> listeners;
//        try {
//            listeners = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getHttpListeners);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine,listeners);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getHttpListeners());
    }


    /**
     * This method is used to remove an HTTP listener that has been registered by the extension.
     *
     * @param listener The HTTP listener to be removed.
     */
    public void removeHttpListener(IHttpListener listener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeHttpListener(listener));
    }


    /**
     * This method is used to register a listener which will be notified of requests and responses being processed by
     * the Proxy tool. Extensions can perform custom analysis or modification of these messages, and control in-UI
     * message interception, by registering a proxy listener.
     *
     * @param listener An object created by the extension that implements the {@link burp.IProxyListener} interface.
     * @return The instance of {@link burp.IProxyListener} that was created.
     */
    public IProxyListener registerProxyListener(Object listener) {
        final IProxyListener l = Helpers.<IProxyListener>wrapInterface(listener, ProxyListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerProxyListener(l));
        return l;
    }


    /**
     * This method is used to retrieve the Proxy listeners that are registered by the extension.
     *
     * @return A list of Proxy listeners that are currently registered by this extension.
     */
    public JSObject getProxyListeners() {
//        List<IProxyListener> listeners;
//        try {
//            listeners = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getProxyListeners);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, listeners);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getProxyListeners());
    }

    /**
     * This method is used to remove a Proxy listener that has been registered by the extension.
     *
     * @param listener The Proxy listener to be removed.
     */
    public void removeProxyListener(IProxyListener listener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeProxyListener(listener));
    }


    /**
     * This method is used to register a listener which will be notified of new issues that are reported by the Scanner
     * tool. Extensions can perform custom analysis or logging of Scanner issues by registering a Scanner listener.
     *
     * @param listener A list of Scanner listeners that are currently registered by this extension.
     * @return The instance of {@link burp.IScannerListener} that was created.
     */
    public IScannerListener registerScannerListener(Object listener) {
        final IScannerListener l = Helpers.<IScannerListener>wrapInterface(listener, ScannerListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScannerListener(l));
        return l;
    }


    /**
     * This method is used to retrieve the Scanner listeners that are registered by the extension.
     *
     * @return A list of Scanner listeners that are currently registered by this extension.
     */
    public JSObject getScannerListeners() {
//        List<IScannerListener> listeners;
//        try {
//            listeners = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getScannerListeners);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, listeners);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getScannerListeners());
    }


    /**
     * This method is used to remove a Scanner listener that has been registered by the extension.
     *
     * @param listener The Scanner listener to be removed.
     */
    public void removeScannerListener(IScannerListener listener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScannerListener(listener));
    }


    /**
     * This method is used to register a listener which will be notified of changes to Burp's suite-wide target scope.
     *
     * @param listener An object created by the extension that implements the {@link burp.IScopeChangeListener}
     *                 interface.
     * @return The instance of {@link burp.IScopeChangeListener} that was created.
     */
    public IScopeChangeListener registerScopeChangeListener(Object listener) {
        final IScopeChangeListener l = Helpers.<IScopeChangeListener>wrapInterface(listener, ScopeChangeListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScopeChangeListener(l));
        return l;
    }


    /**
     * This method is used to retrieve the scope change listeners that are registered by the extension.
     *
     * @return A list of scope change listeners that are currently registered by this extension.
     */
    public JSObject getScopeChangeListeners() {
//        List<IScopeChangeListener> listeners;
//        try {
//            listeners = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getScopeChangeListeners);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, listeners);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getScopeChangeListeners());
    }

    /**
     * This method is used to remove a scope change listener that has been registered by the extension.
     *
     * @param listener The Listener to be removed.
     */
    public void removeScopeChangeListener(IScopeChangeListener listener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScopeChangeListener(listener));
    }


    /**
     * This method is used to register a factory for custom context menu items. When the user invokes a context menu
     * anywhere within Burp, the factory will be passed details of the invocation event, and asked to provide any
     * custom context menu items that should be shown.
     *
     * @param factory An object created by the extension that implements the {@link burp.IContextMenuFactory} interface.
     * @return The instance of {@link burp.IContextMenuFactory} that was created.
     */
    public IContextMenuFactory registerContextMenuFactory(Object factory) {
        final IContextMenuFactory f = Helpers.<IContextMenuFactory>wrapInterface(factory, ContextMenuFactoryJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerContextMenuFactory(f));
        return f;
    }


    /**
     * This method is used to retrieve the context menu factories that are registered by the extension.
     *
     * @return A list of context menu factories that are currently registered by this extension.
     */
    public JSObject getContextMenuFactories() {
//        List<IContextMenuFactory> listeners;
//        try {
//            listeners = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getContextMenuFactories);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, listeners);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getContextMenuFactories());
    }


    /**
     * This method is used to remove a context menu factory that has been registered by the extension.
     *
     * @param factory The context menu factory to be removed.
     */
    public void removeContextMenuFactory(IContextMenuFactory factory) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeContextMenuFactory(factory));
    }


    /**
     * This method is used to register a factory for custom message editor tabs. For each message editor that already
     * exists, or is subsequently created, within Burp, the factory will be asked to provide a new instance of an
     * {@link burp.IMessageEditorTab} object, which can provide custom rendering or editing of HTTP messages.
     *
     * @param factory An object created by the extension that implements the {@link burp.IMessageEditorTabFactory}
     *                interface.
     * @return The instance of the {@link burp.IMessageEditorTabFactory} that was created.
     */
    public IMessageEditorTabFactory registerMessageEditorTabFactory(Object factory) {
        final IMessageEditorTabFactory f = Helpers.<IMessageEditorTabFactory>wrapInterface(factory, MessageEditorTabFactoryJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerMessageEditorTabFactory(f));
        return f;
    }


    /**
     * This method is used to retrieve the message editor tab factories that are registered by the extension.
     *
     * @return A list of message editor tab factories that are currently registered by this extension.
     */
    public JSObject getMessageEditorTabFactories() {
//        List<IMessageEditorTabFactory> factories;
//        try {
//            factories = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getMessageEditorTabFactories);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, factories);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getMessageEditorTabFactories());
    }


    /**
     * This method is used to remove a message editor tab factory that has been registered by the extension.
     *
     * @param factory The message editor tab factory to be removed.
     */
    public void removeMessageEditorTabFactory(IMessageEditorTabFactory factory) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeMessageEditorTabFactory(factory));
    }


    /**
     * This method is used to register a provider of Scanner insertion points. For each base request that is actively
     * scanned, Burp will ask the provider to provide any custom scanner insertion points that are appropriate for the
     * request.
     *
     * @param provider An object created by the extension that implements
     *                 the {@link burp.IScannerInsertionPointProvider} interface.
     * @return The instance of {@link burp.IScannerInsertionPointProvider} that was created.
     */
    public IScannerInsertionPointProvider registerScannerInsertionPointProvider(Object provider) {
        final IScannerInsertionPointProvider p = Helpers.<IScannerInsertionPointProvider>wrapInterface(provider, ScannerInsertionPointProviderJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScannerInsertionPointProvider(p));
        return p;
    }


    /**
     * This method is used to retrieve the Scanner insertion point providers that are registered by the extension.
     *
     * @return A list of Scanner insertion point providers that are currently registered by this extension.
     */
    public JSObject getScannerInsertionPointProviders() {
//        List<IScannerInsertionPointProvider> providers;
//        try {
//            providers = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getScannerInsertionPointProviders);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, providers);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getScannerInsertionPointProviders());
    }


    /**
     * This method is used to remove a Scanner insertion point provider that has been registered by the extension.
     *
     * @param provider The Scanner insertion point provider to be removed.
     */
    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScannerInsertionPointProvider(provider));
    }


    /**
     * This method is used to register a custom Scanner check. When performing scanning, Burp will ask the check to
     * perform active or passive scanning on the base request, and report any Scanner issues that are identified.
     *
     * @param check An object created by the extension that implements the {@link burp.IScannerCheck} interface.
     * @return The instance of {@link burp.IScannerCheck} that was created.
     */
    public IScannerCheck registerScannerCheck(Object check) {
        final IScannerCheck c = Helpers.<IScannerCheck>wrapInterface(check, ScannerCheckJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScannerCheck(c));
        return c;
    }


    /**
     * This method is used to retrieve the Scanner checks that are registered by the extension.
     *
     * @return A list of Scanner checks that are currently registered by this extension.
     */
    public JSObject getScannerChecks() {
//        List<IScannerCheck> checks;
//        try {
//            checks = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getScannerChecks);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, checks);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getScannerChecks());
    }


    /**
     * This method is used to remove a Scanner check that has been registered by the extension.
     *
     * @param check The Scanner check to be removed.
     */
    public void removeScannerCheck(IScannerCheck check) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScannerCheck(check));
    }


    /**
     * This method is used to register a factory for Intruder payloads. Each registered factory will be available within
     * the Intruder UI for the user to select as the payload source for an attack. When this is selected, the factory
     * will be asked to provide a new instance of an {@link burp.IIntruderPayloadGeneratorFactory} object, which will
     * be used to generate payloads for the attack.
     *
     * @param factory An object created by the extension that implements
     *                the {@link burp.IIntruderPayloadGeneratorFactory} interface.
     * @return The instance of {@link burp.IIntruderPayloadGeneratorFactory} that was created.
     */
    public IIntruderPayloadGeneratorFactory registerIntruderPayloadGeneratorFactory(Object factory) {
        final IIntruderPayloadGeneratorFactory f = Helpers.<IIntruderPayloadGeneratorFactory>wrapInterface(factory, IntruderPayloadGeneratorFactoryJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerIntruderPayloadGeneratorFactory(f));
        return f;
    }


    /**
     * This method is used to retrieve the Intruder payload generator factories that are registered by the extension.
     *
     * @return A list of Intruder payload generator factories that are currently registered by this extension.
     */
    public JSObject getIntruderPayloadGeneratorFactories() {
//        List<IIntruderPayloadGeneratorFactory> factories;
//        try {
//            factories = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getIntruderPayloadGeneratorFactories);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, factories);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getIntruderPayloadGeneratorFactories());
    }


    /**
     * This method is used to remove an Intruder payload generator factory that has been registered by the extension.
     *
     * @param factory The Intruder payload generator factory to be removed.
     */
    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeIntruderPayloadGeneratorFactory(factory));
    }


    /**
     * This method is used to register a custom Intruder payload processor. Each registered processor will be available
     * within the Intruder UI for the user to select as the action for a payload processing rule.
     *
     * @param processor An object created by the extension that implements the {@link burp.IIntruderPayloadProcessor}
     *                  interface.
     * @return The instance of {@link burp.IIntruderPayloadProcessor} that was created.
     */
    public IIntruderPayloadProcessor registerIntruderPayloadProcessor(Object processor) {
        final IIntruderPayloadProcessor p = Helpers.<IIntruderPayloadProcessor>wrapInterface(processor, IntruderPayloadProcessorJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerIntruderPayloadProcessor(p));
        return p;
    }


    /**
     * This method is used to retrieve the Intruder payload processors that are registered by the extension.
     *
     * @return A list of Intruder payload processors that are currently registered by this extension.
     */
    public JSObject getIntruderPayloadProcessors() {
//        List<IIntruderPayloadProcessor> processors;
//        try {
//            processors = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getIntruderPayloadProcessors);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, processors);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getIntruderPayloadProcessors());
    }


    /**
     * This method is used to remove an Intruder payload processor that has been registered by the extension.
     *
     * @param processor The Intruder payload processor to be removed.
     */
    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeIntruderPayloadProcessor(processor));
    }


    /**
     * This method is used to register a custom session handling action. Each registered action will be available within
     * the session handling rule UI for the user to select as a rule action. Users can choose to invoke an action
     * directly in its own right, or following execution of a macro.
     *
     * @param action An object created by the extension that implements the {@link burp.ISessionHandlingAction}
     *               interface.
     * @return The instance of {@link burp.ISessionHandlingAction} that was created.
     */
    public ISessionHandlingAction registerSessionHandlingAction(Object action) {
        final ISessionHandlingAction a = Helpers.<ISessionHandlingAction>wrapInterface(action, SessionHandlingActionJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerSessionHandlingAction(a));
        return a;
    }


    /**
     * This method is used to retrieve the session handling actions that are registered by the extension.
     *
     * @return This method is used to retrieve the session handling actions that are registered by the extension.
     */
    public JSObject getSessionHandlingActions() {
//        List<ISessionHandlingAction> actions;
//        try {
//            actions = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getSessionHandlingActions);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, actions);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getSessionHandlingActions());
    }


    /**
     * This method is used to remove a session handling action that has been registered by the extension.
     *
     * @param action The extension session handling action to be removed.
     */
    public void removeSessionHandlingAction(ISessionHandlingAction action) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeSessionHandlingAction(action));
    }


    /**
     * This method is used to unload the extension from Burp Suite.
     */
    public void unloadExtension() {
        SwingUtilities.invokeLater(burpExtenderCallbacks::unloadExtension);
    }


    /**
     * This method is used to add a custom tab to the main Burp Suite window.
     *
     * @param tab An object created by the extension that implements the {@link burp.ITab} interface.
     * @return The instance of {@link burp.ITab} that was created.
     */
    public ITab addSuiteTab(Object tab) {
        final ITab t = Helpers.<ITab>wrapInterface(tab, TabJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.addSuiteTab(t));
        return t;
    }


    /**
     * This method is used to remove a previously-added tab from the main Burp Suite window.
     *
     * @param tab An object created by the extension that implements the {@link burp.ITab} interface.
     */
    public void removeSuiteTab(ITab tab) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeSuiteTab(tab));
    }


    /**
     * This method is used to customize UI components in line with Burp's UI style, including font size, colors, table
     * line spacing, etc. The action is performed recursively on any child components of the passed-in component.
     *
     * @param component The UI component to be customized.
     */
    public void customizeUiComponent(Component component) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.customizeUiComponent(component));
    }


    /**
     * This method is used to create a new instance of Burp's HTTP message editor, for the extension to use in its own
     * UI.
     *
     * @param controller An object created by the extension that implements the {@link burp.IMessageEditorController}
     *                   interface. This parameter is optional and may be {@code null}. If it is provided, then the
     *                   message editor will query the controller when required to obtain details about the currently
     *                   displayed message, including the {@link burp.IHttpService} for the message, and the associated
     *                   request or response message. If a controller is not provided, then the message editor will not
     *                   support context menu actions, such as sending requests to other Burp tools.
     * @param editable   Indicates whether the editor created should be editable, or used only for message viewing.
     * @param callback   A JavaScript callback function that will be called once the {@link burp.IMessageEditor}
     *                   instance is created. The instance of {@link burp.IMessageEditor} will be passed to the callback
     *                   function as the first parameter.
     */
    public void createMessageEditor(IMessageEditorController controller, boolean editable, JSObject callback) {
        SwingFXUtilities.invokeLater(
                () -> burpExtenderCallbacks.createMessageEditor(controller, editable),
                callback
        );
    }


    /**
     * This method returns the command line arguments that were passed to Burp on startup.
     *
     * @return The command line arguments that were passed to Burp on startup.
     */
    public JSObject getCommandLineArguments() {
//        String[] arguments;
//        try {
//            arguments = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getCommandLineArguments);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, arguments);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getCommandLineArguments());
    }


    /**
     * This method is used to save configuration settings for the extension in a persistent way that survives reloads of
     * the extension and of Burp Suite. Saved settings can be retrieved using the method
     * {@link #loadExtensionSetting(String)}.
     *
     * @param name  The name of the setting.
     * @param value The value of the setting. If this value is {@code null} then any existing setting with the specified
     *              name will be removed.
     */
    public void saveExtensionSetting(String name, String value) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.saveExtensionSetting(name, value));
    }


    /**
     * This method is used to load configuration settings for the extension that were saved using the method
     * {@link #saveExtensionSetting(String, String)}.
     *
     * @param name The name of the setting.
     * @return The value of the setting, or {@code null} if no value is set.
     */
    public synchronized String loadExtensionSetting(String name) {
        final String string;
        try {
            string = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.loadExtensionSetting(name));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return string;
    }


    /**
     * This method is used to create a new instance of Burp's plain text editor, for the extension to use in its own UI.
     *
     * @param callback a JavaScript callback function that is called with an instance of {@link burp.ITextEditor} as its
     *                 first argument once the {@link burp.ITextEditor} instance has been successfully created.
     */
    public void createTextEditor(JSObject callback) {
        SwingFXUtilities.invokeLater(
                burpExtenderCallbacks::createTextEditor,
                callback
        );
    }


    /**
     * This method can be used to send an HTTP request to the Burp Repeater tool. The request will be displayed in the
     * user interface, but will not be issued until the user initiates this action.
     *
     * @param host          The hostname of the remote HTTP server.
     * @param port          The port of the remote HTTP server.
     * @param useHttps      Flags whether the protocol is HTTPS or HTTP.
     * @param request       The full HTTP request.
     * @param tabCaption    An optional caption which will appear on the Repeater tab containing the request. If this
     *                      value is {@code null} then a default tab index will be displayed.
     */
    public void sendToRepeater(String host, int port, boolean useHttps, Object request, String tabCaption) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToRepeater(
                        host,
                        port,
                        useHttps,
                        getBytes(request),
                        tabCaption
                )
        );
    }


    /**
     * Does the same thing as {@link #sendToRepeater(String, int, boolean, Object, String)} with less effort for HTTP
     * GET requests.
     *
     * This method will automatically build an HTTP GET request by simply processing the URL and inserting cookie
     * information from the WebKit/JavaFX cookie jar.
     *
     * @param url           The URL of the request to send to the repeater.
     * @param tabCaption    An optional caption which will appear on the Repeater tab containing the request. If this
     *                      value is {@code null} then a default tab index will be displayed.
     * @throws IOException
     * @throws URISyntaxException
     */
    public void sendUrlToRepeater(String url, String tabCaption) throws IOException, URISyntaxException {
        URL urlObject = getNormalizedURL(url);

        sendToRepeater(
                urlObject.getHost(),
                urlObject.getPort(),
                isHttps(urlObject),
                buildHttpRequestWithCookies(urlObject),
                tabCaption
        );
    }


    /**
     * This method can be used to send an HTTP request to the Burp Intruder tool. The request will be displayed in the
     * user interface, and markers for attack payloads will be placed into default locations within the request.
     *
     * @param host      The hostname of the remote HTTP server.
     * @param port      The port of the remote HTTP server.
     * @param useHttps  Flags whether the protocol is HTTPS or HTTP.
     * @param request   The full HTTP request.
     */
    public void sendToIntruder(String host, int port, boolean useHttps, Object request) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToIntruder(host, port, useHttps, getBytes(request)));
    }


    /**
     * Does the same thing as {@link #sendToIntruder(String, int, boolean, Object)} with less effort for HTTP GET
     * requests.
     *
     * This method will automatically build an HTTP GET request by simply processing the URL and inserting cookie
     * information from the WebKit/JavaFX cookie jar.
     *
     * @param url The URL of the request to send to the intruder.
     * @throws IOException
     * @throws URISyntaxException
     */
    public void sendUrlToIntruder(String url) throws IOException, URISyntaxException {
        URL urlObject = getNormalizedURL(url);

        sendToIntruder(
                urlObject.getHost(),
                urlObject.getPort(),
                isHttps(urlObject),
                buildHttpRequestWithCookies(urlObject)
        );
    }


    /**
     * This method can be used to send an HTTP request to the Burp Intruder tool. The request will be displayed in the
     * user interface, and markers for attack payloads will be placed into the specified locations within the request.
     *
     * @param host                      The hostname of the remote HTTP server.
     * @param port                      The port of the remote HTTP server.
     * @param useHttps                  Flags whether the protocol is HTTPS or HTTP.
     * @param request                   The full HTTP request.
     * @param payloadPositionOffsets    A list of index pairs representing the payload positions to be used. Each item
     *                                  in the list must be an {@code int[2]} array containing the start and end offsets
     *                                  for the payload position.
     */
    public void sendToIntruder2(String host, int port, boolean useHttps, Object request, Object payloadPositionOffsets) {
        final List<int[]> payloadPositions = (payloadPositionOffsets instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) payloadPositionOffsets):(List<int[]>)payloadPositionOffsets;
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToIntruder(host, port, useHttps, getBytes(request), payloadPositions));
    }


    /**
     * This method can be used to send data to the Comparer tool.
     *
     * @param data The data to be sent to Comparer.
     */
    public void sendToComparer(Object data) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToComparer(getBytes(data)));
    }


    /**
     * This method can be used to send a seed URL to the Burp Spider tool. If the URL is not within the current Spider
     * scope, the user will be asked if they wish to add the URL to the scope. If the Spider is not currently running,
     * it will be started. The seed URL will be requested, and the Spider will process the application's response in
     * the normal way.
     *
     * @param url The new seed URL to begin spidering from.
     * @throws MalformedURLException
     */
    public void sendToSpider(String url) throws MalformedURLException {
        final URL urlObject = new URL(url);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToSpider(urlObject));
    }


    /**
     * This method can be used to send an HTTP request to the Burp Scanner tool to perform an active vulnerability scan.
     * If the request is not within the current active scanning scope, the user will be asked if they wish to proceed
     * with the scan.
     *
     * @param host      The hostname of the remote HTTP server.
     * @param port      The port of the remote HTTP server.
     * @param useHttps  Flags whether the protocol is HTTPS or HTTP.
     * @param request   The full HTTP request.
     * @param callback  A JavaScript callback function that gets called with an instance of {@link burp.IScanQueueItem}
     *                  as its first argument once successfully created.
     */
    public void doActiveScan(String host, int port, boolean useHttps, Object request, JSObject callback) {
        SwingFXUtilities.invokeLater(
                () -> burpExtenderCallbacks.doActiveScan(host, port, useHttps, getBytes(request)),
                callback
        );
    }


    /**
     *
     * @param host                  The hostname of the remote HTTP server.
     * @param port                  The port of the remote HTTP server.
     * @param useHttps              Flags whether the protocol is HTTPS or HTTP.
     * @param request               The full HTTP request.
     * @param insertionPointOffsets A list of index pairs representing the positions of the insertion points that should
     *                              be scanned. Each item in the list must be an {@code int[2]} array containing the
     *                              start and end offsets for the insertion point.
     * @param callback              A JavaScript callback function that gets called with an instance
     *                              of {@link burp.IScanQueueItem} as its first argument once successfully created.
     */
    public void doActiveScan2(String host, int port, boolean useHttps, Object request, Object insertionPointOffsets, JSObject callback) {
        final List<int[]> insertionPoints = (insertionPointOffsets instanceof JSObject)?
                Helpers.toTwoDimensionalJavaListIntArray((JSObject) insertionPointOffsets):(List<int[]>)insertionPointOffsets;
        SwingFXUtilities.invokeLater(
                () -> burpExtenderCallbacks.doActiveScan(host, port, useHttps, getBytes(request), insertionPoints),
                callback
        );
    }

    /**
     * Does the same thing as {@link #doActiveScan(String, int, boolean, Object, JSObject)} with less effort for HTTP
     * GET requests.
     *
     * @param url       The URL of the request to send to the scanner.
     * @param callback  A JavaScript callback function that gets called with an instance
     *                  of {@link burp.IScanQueueItem} as its first argument once successfully created.
     * @throws IOException
     * @throws URISyntaxException
     */
    public void doActiveUrlScan(String url, JSObject callback) throws IOException, URISyntaxException {
        URL urlObject = getNormalizedURL(url);

        doActiveScan(
                urlObject.getHost(),
                urlObject.getPort(),
                isHttps(urlObject),
                buildHttpRequestWithCookies(urlObject),
                callback
        );
    }


    /**
     * This method can be used to send an HTTP request to the Burp Scanner tool to perform a passive vulnerability scan.
     *
     * @param host      The hostname of the remote HTTP server.
     * @param port      The port of the remote HTTP server.
     * @param useHttps  Flags whether the protocol is HTTPS or HTTP.
     * @param request   The full HTTP request.
     * @param response  The full HTTP response.
     */
    public void doPassiveScan(String host, int port, boolean useHttps, Object request, Object response) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.doPassiveScan(host, port, useHttps, getBytes(request), getBytes(response)));
    }


    /**
     * This method can be used to issue HTTP requests and retrieve their responses.
     *
     * @param httpService   The HTTP service to which the request should be sent.
     * @param request       The full HTTP request.
     * @return an instance of {@link burp.IHttpRequestResponse}.
     */
    public IHttpRequestResponse makeHttpRequest(IHttpService httpService, Object request) {
        return burpExtenderCallbacks.makeHttpRequest(httpService, getBytes(request));
    }


    /**
     * A shortcut method to performing HTTP GET requests by providing only the URL.
     *
     * @param url The HTTP service to which the request should be sent.
     * @return an instance of {@link burp.IHttpRequestResponse}.
     * @throws java.net.MalformedURLException
     */
    public IHttpRequestResponse makeUrlHttpRequest(String url) throws IOException, URISyntaxException {
        final URL urlObject = getNormalizedURL(url);
        return makeHttpRequest(
                helpers.buildHttpService(urlObject.getHost(), urlObject.getPort(), isHttps(urlObject)),
                buildHttpRequestWithCookies(urlObject)
        );
    }


    /**
     * This method can be used to issue HTTP requests and retrieve their responses.
     *
     * @param host      The hostname of the remote HTTP server.
     * @param port      The port of the remote HTTP server.
     * @param useHttps  Flags whether the protocol is HTTPS or HTTP.
     * @param request   The full HTTP request.
     * @return a byte array containing the response data.
     */
    public byte[] makeHttpRequest2(String host, int port, boolean useHttps, Object request) {
        return burpExtenderCallbacks.makeHttpRequest(host, port, useHttps, getBytes(request));
    }


    /**
     * A shortcut method to performing HTTP GET requests by providing only the URL.
     *
     * @param url The HTTP service to which the request should be sent.
     * @return a byte array containing the response data.
     * @throws java.net.MalformedURLException
     */
    public byte[] makeUrlHttpRequest2(String url) throws IOException, URISyntaxException {
        final URL urlObject = getNormalizedURL(url);
        return makeHttpRequest2(
                urlObject.getHost(),
                urlObject.getPort(),
                isHttps(urlObject),
                buildHttpRequestWithCookies(urlObject)
        );
    }


    /**
     * This method can be used to query whether a specified URL is within the current Suite-wide scope.
     *
     * @param url The URL to include in the Suite-wide scope.
     * @return true if in scope, otherwise false.
     * @throws MalformedURLException
     */
    public boolean isInScope(String url) throws MalformedURLException {
//        boolean result;
//        final URL urlObject = new URL(url);
//        try {
//            result = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.isInScope(urlObject));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return false;
//        }
//        return result;
        return burpExtenderCallbacks.isInScope(new URL(url));
    }


    /**
     * This method can be used to include the specified URL in the Suite-wide scope.
     *
     * @param url The URL to include in the Suite-wide scope.
     * @throws MalformedURLException
     */
    public void includeInScope(String url) throws MalformedURLException {
        final URL urlObject = new URL(url);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.includeInScope(urlObject));
    }


    /**
     * This method can be used to exclude the specified URL from the Suite-wide scope.
     *
     * @param url The URL to exclude from the Suite-wide scope.
     * @throws MalformedURLException
     */
    public void excludeFromScope(String url) throws MalformedURLException {
        final URL urlObject = new URL(url);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.excludeFromScope(urlObject));
    }


    /**
     * This method can be used to display a specified message in the Burp Suite alerts tab.
     *
     * @param message The alert message to display.
     */
    public void issueAlert(String message) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.issueAlert(message));
    }


    /**
     * This method returns details of all items in the Proxy history.
     *
     * @return The contents of the Proxy history.
     */
    public JSObject getProxyHistory() {
//        IHttpRequestResponse[] httpRequestResponse;
//        try {
//            httpRequestResponse = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getProxyHistory);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, httpRequestResponse);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getProxyHistory());
    }


    /**
     * This method returns details of items in the site map.
     *
     * @param urlPrefix This parameter can be used to specify a URL prefix, in order to extract a specific subset of the
     *                  site map. The method performs a simple case-sensitive text match, returning all site map items
     *                  whose URL begins with the specified prefix. If this parameter is null, the entire site map is
     *                  returned.
     * @return Details of items in the site map.
     */
    public JSObject getSiteMap(String urlPrefix) {
//        IHttpRequestResponse[] httpRequestResponse;
//        try {
//            httpRequestResponse = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.getSiteMap(urlPrefix));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, httpRequestResponse);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getSiteMap(urlPrefix));
    }


    /**
     * This method returns all of the current scan issues for URLs matching the specified literal prefix.
     *
     * @param urlPrefix This parameter can be used to specify a URL prefix, in order to extract a specific subset of
     *                  scan issues. The method performs a simple case-sensitive text match, returning all scan issues
     *                  whose URL begins with the specified prefix. If this parameter is null, all issues are returned.
     * @return Details of the scan issues.
     */
    public JSObject getScanIssues(String urlPrefix) {
//        IScanIssue[] scanIssues;
//        try {
//            scanIssues = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.getScanIssues(urlPrefix));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, scanIssues);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getScanIssues(urlPrefix));
    }


    /**
     * This method is used to generate a report for the specified Scanner issues. The report format can be specified.
     * For all other reporting options, the default settings that appear in the reporting UI wizard are used.
     *
     * @param format    The format to be used in the report. Accepted values are HTML and XML.
     * @param issues    The Scanner issues to be reported.
     * @param file      The file to which the report will be saved.
     */
    public void generateScanReport(String format, Object issues, String file) {
        final IScanIssue[] scanIssues = (issues instanceof JSObject)?Helpers.toJavaArray((JSObject) issues, IScanIssue.class):(IScanIssue[]) issues;
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.generateScanReport(format, scanIssues, new File(file)));
    }


    /**
     * This method is used to retrieve the contents of Burp's session handling cookie jar. Extensions that provide an
     * {@link burp.ISessionHandlingAction} can query and update the cookie jar in order to handle unusual session
     * handling mechanisms.
     *
     * @return A list of {@link burp.ICookie} objects representing the contents of Burp's session handling cookie jar.
     */
    public JSObject getCookieJarContents() {
//        List<ICookie> cookies;
//        try {
//            cookies = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getCookieJarContents);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, cookies);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getCookieJarContents());
    }

    /**
     * This method is used to update the contents of Burp's session handling cookie jar. Extensions that provide an
     * {@link burp.ISessionHandlingAction} can query and update the cookie jar in order to handle unusual session
     * handling mechanisms.
     *
     * @param cookie An {@link burp.ICookie} object containing details of the cookie to be updated. If the cookie jar
     *               already contains a cookie that matches the specified domain and name, then that cookie will be
     *               updated with the new value and expiration, unless the new value is null, in which case the cookie
     *               will be removed. If the cookie jar does not already contain a cookie that matches the specified
     *               domain and name, then the cookie will be added.
     * @return the instance of {@link burp.ICookie} that was used to modify the cookie jar.
     */
    public ICookie updateCookieJar(Object cookie) {
        final ICookie cookieObject = Helpers.<ICookie>wrapInterface(cookie, CookieJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.updateCookieJar(cookieObject));
        return cookieObject;
    }


    /**
     * This method can be used to add an item to Burp's site map with the specified request/response details. This will
     * overwrite the details of any existing matching item in the site map.
     *
     * @param item Details of the item to be added to the site map
     */
    public void addToSiteMap(Object item) {
        final IHttpRequestResponse h = Helpers.<IHttpRequestResponse>wrapInterface(item, HttpRequestResponseJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.addToSiteMap(h));
    }


    /**
     * This method can be used to restore Burp's state from a specified saved state file. This method blocks until the
     * restore operation is completed, and must not be called from the event dispatch thread.
     *
     * @param file The file name containing Burp's saved state.
     */
    public void restoreState(String file) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.restoreState(new File(file)));
    }


    /**
     * This method can be used to save Burp's state to a specified file. This method blocks until the save operation is
     * completed, and must not be called from the event dispatch thread.
     *
     * @param file The file name to save Burp's state in.
     */
    public void saveState(String file) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.saveState(new File(file)));
    }


    /**
     * This method causes Burp to save all of its current configuration as a Map of name/value Strings.
     *
     * @return A Map of name/value Strings reflecting Burp's current configuration.
     * @throws IOException
     */
    public synchronized JSObject saveConfig() throws IOException {
        Map<String, String> config;
        try {
            config = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::saveConfig);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSMap(webEngine, config);
    }


    /**
     * This method causes Burp to load a new configuration from the Map of name/value Strings provided. Any settings not
     * specified in the Map will be restored to their default values. To selectively update only some settings and leave
     * the rest unchanged, you should first call saveConfig() to obtain Burp's current configuration, modify the relevant
     * items in the Map, and then call loadConfig() with the same Map.
     *
     * @param config A map of name/value Strings to use as Burp's new configuration.
     */
    public void loadConfig(JSObject config) {
        Map<String, Object> map = Helpers.toJavaMap(webEngine, config);
        Map<String, String> results = new HashMap<>();

        for (String key : map.keySet())
            results.put(key, map.get(key).toString());

        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.loadConfig(results));
    }


    /**
     * This method sets the master interception mode for Burp Proxy.
     *
     * @param enabled Indicates whether interception of Proxy messages should be enabled.
     */
    public void setProxyInterceptionEnabled(boolean enabled) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.setProxyInterceptionEnabled(enabled));
    }


    /**
     * This method retrieves information about the version of Burp in which the extension is running. It can be used by
     * extensions to dynamically adjust their behavior depending on the functionality and APIs supported by the current
     * version.
     *
     * @return An array of Strings comprised of: the product name (e.g. Burp Suite Professional), the major version
     * (e.g. 1.5), the minor version (e.g. 03)
     */
    public JSObject getBurpVersion() {
//        String[] version = null;
//        try {
//            version = SwingFXUtilities.invokeAndWait(burpExtenderCallbacks::getBurpVersion);
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//        }
//        return Helpers.toJSArray(webEngine, version);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getBurpVersion());
    }


    /**
     * This method can be used to shut down Burp programmatically, with an optional prompt to the user. If the method
     * returns, the user canceled the shutdown prompt.
     *
     * @param promptUser Indicates whether to prompt the user to confirm the shutdown.
     */
    public void exitSuite(boolean promptUser) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.exitSuite(promptUser));
    }


    /**
     * This method is used to create a temporary file on disk containing the provided data. Extensions can use temporary
     * files for long-term storage of runtime data, avoiding the need to retain that data in memory.
     *
     * @param buffer The data to be saved to a temporary file.
     * @return An object that implements the {@link burp.ITempFile} interface.
     */
    public ITempFile saveToTempFile(Object buffer) {
        byte[] bufferObject = getBytes(buffer);
        ITempFile tempFile;
        try {
            tempFile = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.saveToTempFile(bufferObject));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return tempFile;
    }


    /**
     * This method is used to save the request and response of an IHttpRequestResponse object to temporary files, so
     * that they are no longer held in memory. Extensions can used this method to convert IHttpRequestResponse objects
     * into a form suitable for long-term storage.
     *
     * @param httpRequestResponse The {@link burp.IHttpRequestResponse} object whose request and response messages are
     *                            to be saved to temporary files.
     * @return An object that implements the {@link burp.IHttpRequestResponsePersisted} interface.
     */
    public synchronized IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse) {
        IHttpRequestResponsePersisted requestResponsePersisted;
        try {
            requestResponsePersisted = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.saveBuffersToTempFiles(httpRequestResponse));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return requestResponsePersisted;
    }


    /**
     * This method is used to apply markers to an HTTP request or response, at offsets into the message that are
     * relevant for some particular purpose. Markers are used in various situations, such as specifying Intruder payload
     * positions, Scanner insertion points, and highlights in Scanner issues.
     *
     * @param httpRequestResponse   The {@link burp.IHttpRequestResponse} object to which the markers should be applied.
     * @param requestMarkers        A list of index pairs representing the offsets of markers to be applied to the
     *                              request message. Each item in the list must be an {@code int[2]} array containing
     *                              the start and end offsets for the marker. The markers in the list should be in
     *                              sequence and not overlapping. This parameter is optional and may be null if no
     *                              request markers are required.
     * @param responseMarkers       A list of index pairs representing the offsets of markers to be applied to the
     *                              response message. Each item in the list must be an {@code int[2]} array containing
     *                              the start and end offsets for the marker. The markers in the list should be in
     *                              sequence and not overlapping. This parameter is optional and may be null if no
     *                              response markers are required.
     * @return An object that implements the {@link burp.IHttpRequestResponseWithMarkers} interface.
     */
    public synchronized IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse httpRequestResponse, Object requestMarkers, Object responseMarkers) {
        List<int[]>reqMarkers = (requestMarkers instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) requestMarkers):(List<int[]>) requestMarkers;
        List<int[]>resMarkers = (responseMarkers instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) responseMarkers):(List<int[]>) responseMarkers;
        IHttpRequestResponseWithMarkers requestResponseWithMarkers;
        try {
            requestResponseWithMarkers = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.applyMarkers(httpRequestResponse, reqMarkers, resMarkers));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return requestResponseWithMarkers;
    }


    /**
     * This method is used to obtain the descriptive name for the Burp tool identified by the tool flag provided.
     *
     * @param i A flag identifying a Burp tool ( TOOL_PROXY, TOOL_SCANNER, etc.). Tool flags are defined within this
     *          interface.
     * @return The descriptive name for the specified tool.
     */
    public String getToolName(int i) {
//        String toolName;
//        try {
//            toolName = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.getToolName(i));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return toolName;
        return burpExtenderCallbacks.getToolName(i);
    }


    /**
     * This method is used to register a new Scanner issue. Note: Wherever possible, extensions should implement custom
     * Scanner checks using IScannerCheck and report issues via those checks, so as to integrate with Burp's user-driven
     * workflow, and ensure proper consolidation of duplicate reported issues. This method is only designed for tasks
     * outside of the normal testing workflow, such as importing results from other scanning tools.
     *
     * @param issue An object created by the extension that implements the IScanIssue interface.
     * @return The instance of {@link burp.IScanIssue} that was created.
     */
    public IScanIssue addScanIssue(Object issue) {
        final IScanIssue i = Helpers.<IScanIssue>wrapInterface(issue, ScanIssueJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.addScanIssue((IScanIssue) issue));
        return i;
    }


    @Deprecated
    /**
     * @deprecated Use {@link burp.IExtensionHelpers#analyzeRequest()} instead. This method parses the specified request
     *             and returns details of each request parameter.
     *
     * @param request The request to be parsed.
     * @return An array of: String[] { name, value, type } containing details of the parameters contained within the request.
     */
    public JSObject getParameters(Object request) {
//        Object[][] parameters;
//        try {
//            parameters = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.getParameters(getBytes(request)));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toTwoDimensionalJSArray(webEngine, parameters);
        return Helpers.toTwoDimensionalJSArray(webEngine, burpExtenderCallbacks.getParameters(getBytes(request)));
    }


    @Deprecated
    /**
     * @deprecated Use {@link burp.IExtensionHelpers#analyzeRequest()} or {@link burp.IExtensionHelpers#analyzeResponse()} instead.
     *             This method parses the specified request and returns details of each HTTP header.
     *
     * @param request The request to be parsed.
     * @return An array of HTTP headers.
     */
    public JSObject getHeaders(Object request) {
//        String[] headers;
//        try {
//            headers = SwingFXUtilities.invokeAndWait(() -> burpExtenderCallbacks.getHeaders(getBytes(request)));
//        } catch (InterruptedException | InvocationTargetException e) {
//            e.printStackTrace();
//            return null;
//        }
//        return Helpers.toJSArray(webEngine, headers);
        return Helpers.toJSArray(webEngine, burpExtenderCallbacks.getHeaders(getBytes(request)));
    }


    /**
     * @deprecated Use registerContextMenuFactory() instead. This method can be used to register a new menu item which
     * will appear on the various context menus that are used throughout Burp Suite to handle user-driven actions.
     *
     * @param menuItemCaption The caption to be displayed on the menu item.
     * @param menuItemHandler The handler to be invoked when the user clicks on the menu item.
     * @return The instance of {@link burp.IMenuItemHandler} that was created.
     */
    public IMenuItemHandler registerMenuItem(String menuItemCaption, Object menuItemHandler) {
        final IMenuItemHandler menuItem = Helpers.<IMenuItemHandler>wrapInterface(menuItemHandler, MenuItemHandlerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerMenuItem(menuItemCaption, menuItem));
        return menuItem;
    }
}