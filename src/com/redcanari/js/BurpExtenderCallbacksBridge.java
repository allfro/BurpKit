package com.redcanari.js;

import burp.*;
import com.redcanari.js.proxies.*;
import com.redcanari.swing.SwingUtilitiesX;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by ndouba on 14-11-16.
 */
@SuppressWarnings({"UnusedDeclaration", "unchecked"})
public class BurpExtenderCallbacksBridge {

    int TOOL_SUITE = 1;
    int TOOL_TARGET = 2;
    int TOOL_PROXY = 4;
    int TOOL_SPIDER = 8;
    int TOOL_SCANNER = 16;
    int TOOL_INTRUDER = 32;
    int TOOL_REPEATER = 64;
    int TOOL_SEQUENCER = 128;
    int TOOL_DECODER = 256;
    int TOOL_COMPARER = 512;
    int TOOL_EXTENDER = 1024;

    IBurpExtenderCallbacks burpExtenderCallbacks;
    WebEngine webEngine;


    public BurpExtenderCallbacksBridge(WebEngine webEngine, IBurpExtenderCallbacks burpExtenderCallbacks) {
        this.burpExtenderCallbacks = burpExtenderCallbacks;
        this.webEngine = webEngine;
    }


    private <T> T wrapInterface(Object object, Class<?> proxyClass) {
        if (object instanceof JSObject) {
            try {
                object = proxyClass.getDeclaredConstructor(JSObject.class).newInstance(object);
            } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                e.printStackTrace();
            }
        }
        return (T) object;
    }


    private byte[] normalizeBytes(Object bytes) {
        if (bytes instanceof String)
            bytes = getHelpers().stringToBytes((String) bytes);
        else if (bytes instanceof JSObject)
            bytes = Helpers.toPrimitiveByteArray(Helpers.<Integer>toJavaArray((JSObject) bytes, Integer.class));
        return (byte[]) bytes;
    }


    public void setExtensionName(String name) {
        try {
            SwingUtilities.invokeAndWait(() -> burpExtenderCallbacks.setExtensionName(name));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }


    public IExtensionHelpers getHelpers() {
        return burpExtenderCallbacks.getHelpers();
    }


    public OutputStream getStdout() {
        return burpExtenderCallbacks.getStdout();
    }


    public OutputStream getStderr() {
        return burpExtenderCallbacks.getStderr();
    }


    public void printOutput(String message) {
        try {
            SwingUtilities.invokeAndWait(() -> burpExtenderCallbacks.printOutput(message));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }


    public void printError(String message) {
        try {
            SwingUtilities.invokeAndWait(() -> burpExtenderCallbacks.printError(message));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }


    public IExtensionStateListener registerExtensionStateListener(Object extensionStateListener) {
        final IExtensionStateListener listener = this.<IExtensionStateListener>wrapInterface(extensionStateListener, ExtensionStateListenerJSProxy.class);
        SwingUtilities.invokeLater(
                () -> burpExtenderCallbacks.registerExtensionStateListener(listener)
        );
        return listener;
    }


    public JSObject getExtensionStateListeners() {
        List<IExtensionStateListener> listeners;
        try {
            listeners = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getExtensionStateListeners);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, listeners);
    }


    public void removeExtensionStateListener(IExtensionStateListener extensionStateListener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeExtensionStateListener(extensionStateListener));
    }


    public IHttpListener registerHttpListener(Object httpListener) {
        final IHttpListener listener = this.<IHttpListener>wrapInterface(httpListener, HttpListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerHttpListener(listener));
        return listener;
    }


    public JSObject getHttpListeners() {
        List<IHttpListener> listeners;
        try {
            listeners = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getHttpListeners);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine,listeners);
    }


    public void removeHttpListener(IHttpListener httpListener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeHttpListener(httpListener));
    }


    public IProxyListener registerProxyListener(Object proxyListener) {
        final IProxyListener listener = this.<IProxyListener>wrapInterface(proxyListener, ProxyListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerProxyListener(listener));
        return listener;
    }


    public JSObject getProxyListeners() {
        List<IProxyListener> listeners;
        try {
            listeners = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getProxyListeners);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, listeners);
    }


    public void removeProxyListener(IProxyListener proxyListener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeProxyListener(proxyListener));
    }


    public IScannerListener registerScannerListener(Object scannerListener) {
        final IScannerListener listener = this.<IScannerListener>wrapInterface(scannerListener, ScannerListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScannerListener(listener));
        return listener;
    }


    public JSObject getScannerListeners() {
        List<IScannerListener> listeners;
        try {
            listeners = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getScannerListeners);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, listeners);
    }


    public void removeScannerListener(IScannerListener scannerListener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScannerListener(scannerListener));
    }


    public IScopeChangeListener registerScopeChangeListener(Object scopeChangeListener) {
        final IScopeChangeListener listener = this.<IScopeChangeListener>wrapInterface(scopeChangeListener, ScopeChangeListenerJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScopeChangeListener(listener));
        return listener;
    }


    public JSObject getScopeChangeListeners() {
        List<IScopeChangeListener> listeners;
        try {
            listeners = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getScopeChangeListeners);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, listeners);
    }


    public void removeScopeChangeListener(IScopeChangeListener scopeChangeListener) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScopeChangeListener(scopeChangeListener));
    }


    public IContextMenuFactory registerContextMenuFactory(Object contextMenuFactory) {
        final IContextMenuFactory factory = this.<IContextMenuFactory>wrapInterface(contextMenuFactory, ContextMenuFactoryJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerContextMenuFactory(factory));
        return factory;
    }


    public JSObject getContextMenuFactories() {
        List<IContextMenuFactory> listeners;
        try {
            listeners = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getContextMenuFactories);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, listeners);
    }


    public void removeContextMenuFactory(IContextMenuFactory contextMenuFactory) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeContextMenuFactory(contextMenuFactory));
    }


    public IMessageEditorTabFactory registerMessageEditorTabFactory(Object messageEditorTabFactory) {
        final IMessageEditorTabFactory factory = this.<IMessageEditorTabFactory>wrapInterface(messageEditorTabFactory, MessageEditorTabFactoryJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerMessageEditorTabFactory(factory));
        return factory;
    }


    public JSObject getMessageEditorTabFactories() {
        List<IMessageEditorTabFactory> factories;
        try {
            factories = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getMessageEditorTabFactories);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, factories);
    }


    public void removeMessageEditorTabFactory(IMessageEditorTabFactory messageEditorTabFactory) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeMessageEditorTabFactory(messageEditorTabFactory));
    }


    public IScannerInsertionPointProvider registerScannerInsertionPointProvider(Object scannerInsertionPointProvider) {
        final IScannerInsertionPointProvider provider = this.<IScannerInsertionPointProvider>wrapInterface(scannerInsertionPointProvider, ScannerInsertionPointProviderJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScannerInsertionPointProvider(provider));
        return provider;
    }


    public JSObject getScannerInsertionPointProviders() {
        List<IScannerInsertionPointProvider> providers;
        try {
            providers = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getScannerInsertionPointProviders);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, providers);
    }


    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider scannerInsertionPointProvider) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScannerInsertionPointProvider(scannerInsertionPointProvider));
    }


    public IScannerCheck registerScannerCheck(Object scannerCheck) {
        final IScannerCheck check = this.<IScannerCheck>wrapInterface(scannerCheck, ScannerCheckJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerScannerCheck(check));
        return check;
    }


    public JSObject getScannerChecks() {
        List<IScannerCheck> checks;
        try {
            checks = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getScannerChecks);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, checks);
    }


    public void removeScannerCheck(IScannerCheck scannerCheck) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeScannerCheck(scannerCheck));
    }


    public IIntruderPayloadGeneratorFactory registerIntruderPayloadGeneratorFactory(Object intruderPayloadGeneratorFactory) {
        final IIntruderPayloadGeneratorFactory factory = this.<IIntruderPayloadGeneratorFactory>wrapInterface(intruderPayloadGeneratorFactory, IntruderPayloadGeneratorFactoryJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerIntruderPayloadGeneratorFactory(factory));
        return factory;
    }


    public JSObject getIntruderPayloadGeneratorFactories() {
        List<IIntruderPayloadGeneratorFactory> factories;
        try {
            factories = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getIntruderPayloadGeneratorFactories);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, factories);
    }


    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory intruderPayloadGeneratorFactory) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeIntruderPayloadGeneratorFactory(intruderPayloadGeneratorFactory));
    }


    public IIntruderPayloadProcessor registerIntruderPayloadProcessor(Object intruderPayloadProcessor) {
        final IIntruderPayloadProcessor processor = this.<IIntruderPayloadProcessor>wrapInterface(intruderPayloadProcessor, IntruderPayloadProcessorJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerIntruderPayloadProcessor(processor));
        return processor;
    }


    public JSObject getIntruderPayloadProcessors() {
        List<IIntruderPayloadProcessor> processors;
        try {
            processors = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getIntruderPayloadProcessors);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, processors);
    }


    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor intruderPayloadProcessor) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeIntruderPayloadProcessor(intruderPayloadProcessor));
    }


    public ISessionHandlingAction registerSessionHandlingAction(Object sessionHandlingAction) {
        final ISessionHandlingAction action = this.<ISessionHandlingAction>wrapInterface(sessionHandlingAction, SessionHandlingActionJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerSessionHandlingAction(action));
        return action;
    }


    public JSObject getSessionHandlingActions() {
        List<ISessionHandlingAction> actions;
        try {
            actions = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getSessionHandlingActions);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, actions);
    }


    public void removeSessionHandlingAction(ISessionHandlingAction sessionHandlingAction) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeSessionHandlingAction(sessionHandlingAction));
    }


    public void unloadExtension() {
        SwingUtilities.invokeLater(burpExtenderCallbacks::unloadExtension);
    }


    public ITab addSuiteTab(Object tab) {
        final ITab tabObject = this.<ITab>wrapInterface(tab, TabJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.addSuiteTab(tabObject));
        return tabObject;
    }


    public void removeSuiteTab(ITab tab) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.removeSuiteTab(tab));
    }


    public void customizeUiComponent(Component component) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.customizeUiComponent(component));
    }


    public void createMessageEditor(IMessageEditorController messageEditorController, boolean editable, JSObject callback) {
        SwingUtilitiesX.invokeLater(
                () -> burpExtenderCallbacks.createMessageEditor(messageEditorController, editable),
                callback
        );
    }


    public JSObject getCommandLineArguments() {
        String[] arguments;
        try {
            arguments = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getCommandLineArguments);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, arguments);
    }


    public void saveExtensionSetting(String name, String value) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.saveExtensionSetting(name, value));
    }


    public String loadExtensionSetting(String name) {
        final String string;
        try {
            string = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.loadExtensionSetting(name));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return string;
    }


    public void createTextEditor(JSObject callback) {
        SwingUtilitiesX.invokeLater(
                burpExtenderCallbacks::createTextEditor,
                callback
        );
    }


    public void sendToRepeater(String host, int port, boolean useHttps, Object request, String tabCaption) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToRepeater(host, port, useHttps, normalizeBytes(request), tabCaption));
    }


    public void sendToIntruder(String host, int port, boolean useHttps, Object request) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToIntruder(host, port, useHttps, normalizeBytes(request)));
    }


    public void sendToIntruder2(String host, int port, boolean useHttps, Object request, Object payloadPositionOffsets) {
        final List<int[]> payloadPositions = (payloadPositionOffsets instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) payloadPositionOffsets):(List<int[]>)payloadPositionOffsets;
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToIntruder(host, port, useHttps, normalizeBytes(request), payloadPositions));
    }


    public void sendToComparer(Object bytes) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToComparer(normalizeBytes(bytes)));
    }

    public void sendToSpider(String url) throws MalformedURLException {
        final URL urlObject = new URL(url);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.sendToSpider(urlObject));
    }

    public void doActiveScan(String host, int port, boolean useHttps, Object request, JSObject callback) {
        SwingUtilitiesX.invokeLater(
                () -> burpExtenderCallbacks.doActiveScan(host, port, useHttps, normalizeBytes(request)),
                callback
        );
    }


    public void doActiveScan2(String host, int port, boolean useHttps, Object request, Object insertionPointOffsets, JSObject callback) {
        final List<int[]> insertionPoints = (insertionPointOffsets instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) insertionPointOffsets):(List<int[]>)insertionPointOffsets;
        SwingUtilitiesX.invokeLater(
                () -> burpExtenderCallbacks.doActiveScan(host, port, useHttps, normalizeBytes(request), insertionPoints),
                callback
        );
    }


    public void doActiveUrlScan(String url, JSObject callback) throws MalformedURLException {
        URL urlObject = new URL(url);
        String host = urlObject.getHost();
        int port = urlObject.getPort();
        boolean useHttps = urlObject.getProtocol().equals("https");
        if (port == -1)
            port = (useHttps)?443:80;

        doActiveScan(host, port, useHttps, getHelpers().buildHttpRequest(urlObject), callback);
    }


    public void doPassiveScan(String host, int port, boolean useHttps, Object request, Object response) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.doPassiveScan(host, port, useHttps, normalizeBytes(request), normalizeBytes(response)));
    }


    public void makeHttpRequest(IHttpService httpService, Object request, JSObject callback) {
        SwingUtilitiesX.invokeLater(
                () -> burpExtenderCallbacks.makeHttpRequest(httpService, normalizeBytes(request)),
                callback
        );
    }


    public void makeHttpRequest2(String host, int port, boolean useHttps, Object request, JSObject callback) {
        SwingUtilitiesX.invokeLater(
                () -> burpExtenderCallbacks.makeHttpRequest(host, port, useHttps, normalizeBytes(request)),
                callback
        );
    }


    public boolean isInScope(String url) throws MalformedURLException {
        boolean result;
        final URL urlObject = new URL(url);
        try {
            result = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.isInScope(urlObject));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return false;
        }
        return result;
    }


    public void includeInScope(String url) throws MalformedURLException {
        final URL urlObject = new URL(url);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.includeInScope(urlObject));
    }


    public void excludeFromScope(String url) throws MalformedURLException {
        final URL urlObject = new URL(url);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.excludeFromScope(urlObject));
    }


    public void issueAlert(String message) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.issueAlert(message));
    }


    public JSObject getProxyHistory() {
        IHttpRequestResponse[] httpRequestResponse;
        try {
            httpRequestResponse = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getProxyHistory);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, httpRequestResponse);
    }


    public JSObject getSiteMap(String urlPrefix) {
        IHttpRequestResponse[] httpRequestResponse;
        try {
            httpRequestResponse = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.getSiteMap(urlPrefix));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, httpRequestResponse);
    }


    public JSObject getScanIssues(String urlPrefix) {
        IScanIssue[] scanIssues;
        try {
            scanIssues = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.getScanIssues(urlPrefix));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, scanIssues);
    }


    public void generateScanReport(String format, Object issues, String file) {
        final IScanIssue[] scanIssues = (issues instanceof JSObject)?Helpers.toJavaArray((JSObject) issues, IScanIssue.class):(IScanIssue[]) issues;
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.generateScanReport(format, scanIssues, new File(file)));
    }


    public JSObject getCookieJarContents() {
        List<ICookie> cookies;
        try {
            cookies = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getCookieJarContents);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, cookies);
    }


    public ICookie updateCookieJar(Object cookie) {
        final ICookie cookieObject = this.<ICookie>wrapInterface(cookie, ICookie.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.updateCookieJar(cookieObject));
        return cookieObject;
    }


    public void addToSiteMap(IHttpRequestResponse httpRequestResponse) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.addToSiteMap(httpRequestResponse));
    }


    public void restoreState(String file) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.restoreState(new File(file)));
    }


    public void saveState(String file) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.saveState(new File(file)));
    }


    public JSObject saveConfig() throws IOException {
        Map<String, String> config;
        try {
            config = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::saveConfig);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSMap(webEngine, config);
    }


    public void loadConfig(JSObject config) {
        Map<String, Object> map = Helpers.toJavaMap(webEngine, config);
        Map<String, String> results = new HashMap<>();

        for (String key : map.keySet())
            results.put(key, map.get(key).toString());

        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.loadConfig(results));
    }


    public void setProxyInterceptionEnabled(boolean enabled) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.setProxyInterceptionEnabled(enabled));
    }


    public JSObject getBurpVersion() {
        String[] version = null;
        try {
            version = SwingUtilitiesX.invokeAndWait(burpExtenderCallbacks::getBurpVersion);
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
        }
        return Helpers.toJSArray(webEngine, version);
    }


    public void exitSuite(boolean promptUser) {
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.exitSuite(promptUser));
    }


    public ITempFile saveToTempFile(Object buffer) {
        byte[] bufferObject = normalizeBytes(buffer);
        ITempFile tempFile;
        try {
            tempFile = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.saveToTempFile(bufferObject));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return tempFile;
    }


    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse) {
        IHttpRequestResponsePersisted requestResponsePersisted;
        try {
            requestResponsePersisted = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.saveBuffersToTempFiles(httpRequestResponse));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return requestResponsePersisted;
    }


    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse httpRequestResponse, Object requestMarkers, Object responseMarkers) {
        List<int[]>reqMarkers = (requestMarkers instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) requestMarkers):(List<int[]>) requestMarkers;
        List<int[]>resMarkers = (responseMarkers instanceof JSObject)?Helpers.toTwoDimensionalJavaListIntArray((JSObject) responseMarkers):(List<int[]>) responseMarkers;
        IHttpRequestResponseWithMarkers requestResponseWithMarkers;
        try {
            requestResponseWithMarkers = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.applyMarkers(httpRequestResponse, reqMarkers, resMarkers));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return requestResponseWithMarkers;
    }


    public String getToolName(int i) {
        String toolName;
        try {
            toolName = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.getToolName(i));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return toolName;
    }


    public IScanIssue addScanIssue(Object scanIssue) {
        final IScanIssue issue = this.<IScanIssue>wrapInterface(scanIssue, ScanIssueJSProxy.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.addScanIssue((IScanIssue) scanIssue));
        return issue;
    }


    public JSObject getParameters(Object request) {
        Object[][] parameters;
        try {
            parameters = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.getParameters(normalizeBytes(request)));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toTwoDimensionalJSArray(webEngine, parameters);
    }


    public JSObject getHeaders(Object request) {
        String[] headers;
        try {
            headers = SwingUtilitiesX.invokeAndWait(() -> burpExtenderCallbacks.getHeaders(normalizeBytes(request)));
        } catch (InterruptedException | InvocationTargetException e) {
            e.printStackTrace();
            return null;
        }
        return Helpers.toJSArray(webEngine, headers);
    }


    public IMenuItemHandler registerMenuItem(String menuItemCaption, Object menuItemHandler) {
        final IMenuItemHandler menuItem = this.<IMenuItemHandler>wrapInterface(menuItemHandler, IMenuItemHandler.class);
        SwingUtilities.invokeLater(() -> burpExtenderCallbacks.registerMenuItem(menuItemCaption, menuItem));
        return menuItem;
    }
}