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

package com.redcanari.ui;

import burp.BurpExtender;
import burp.IMessageEditorController;
import com.dlsc.trafficbrowser.beans.Traffic;
import com.dlsc.trafficbrowser.scene.control.TrafficBrowser;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.redcanari.js.BurpExtenderCallbacksBridge;
import com.redcanari.js.BurpKitBridge;
import com.redcanari.ui.font.FontAwesome;
import com.redcanari.util.ResourceUtils;
import com.sun.javafx.scene.web.Debugger;
import javafx.application.Platform;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.ObservableList;
import javafx.concurrent.Worker;
import javafx.embed.swing.JFXPanel;
import javafx.embed.swing.SwingFXUtils;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebErrorEvent;
import javafx.scene.web.WebEvent;
import javafx.scene.web.WebView;
import javafx.stage.FileChooser;
import javafx.util.Callback;
import netscape.javascript.JSObject;
import org.controlsfx.dialog.Dialogs;

import javax.imageio.ImageIO;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ndouba on 2014-06-01.
 */
public class WebKitBrowser extends JFXPanel {

//    private LocalJSObject locals;
//    private LocalJSObject globals;

    private WebEngine webEngine;
    private WebView webView;
    private Scene scene;
    private IMessageEditorController controller;
    private CollapsibleSplitPane masterDetailPane;
    private ToolBar toolBar;
    private StatusBar statusBar;
    private Button firebugButton;
    private ToggleButton consoleToggleButton;
    private ToggleButton showAlertsToggleButton;
    private AnchorPane webViewAnchorPane;
    private Button screenShotButton;
    private BorderPane masterPane;
    private String originalUserAgent;
    private WebURLField urlTextField;
    private TrafficBrowser trafficBrowser;
    private TabPane detailPane;
    private boolean enabled = false;
    private BurpKitBridge javaScriptHelpers;

    private PageResourcesTab pageResourcesTab;
    private JavaScriptConsoleTab javaScriptConsoleTab;
    private CrossSiteScriptingTrackerTab crossSiteScriptingTrackerTab;

    private final StringProperty numberOfAlerts = new SimpleStringProperty("0");
    private final SimpleBooleanProperty showAlerts = new SimpleBooleanProperty(false);

    private final BooleanProperty isDetailNodeVisible = new SimpleBooleanProperty(true);
    private final List<EventHandler<WebEvent<String>>> alertListeners = new ArrayList<>();
    private final List<EventHandler<WebErrorEvent>> errorListeners = new ArrayList<>();

    private final String selectionScript;
    private final String firebugScript;

    private Dialogs dialog;


    public WebKitBrowser() {
        selectionScript = ResourceUtils.getResourceContentsAsString("/scripts/selectHTML.js");
        firebugScript = ResourceUtils.getResourceContentsAsString("/scripts/launchFirebug.js");
        init();
    }

    public WebKitBrowser(boolean enabled) {
        this.enabled = enabled;
        selectionScript = ResourceUtils.getResourceContentsAsString("/scripts/selectHTML.js");
        firebugScript = ResourceUtils.getResourceContentsAsString("/scripts/launchFirebug.js");
        init();
    }

    public WebKitBrowser(IMessageEditorController controller) {
        this();
        this.controller = controller;
    }

    public WebKitBrowser(IMessageEditorController controller, boolean enabled) {
        this(enabled);
        this.controller = controller;
    }

    private void init() {
        Platform.setImplicitExit(false);
        Platform.runLater(this::createScene);
    }

//    private void addTab(TabPane tabPane, String title, Node node) {
//        Tab tab = new Tab(title);
//        tab.setContent(node);
//        tab.setClosable(false);
//        tabPane.getTabs().add(tab);
//    }

    private void createScene() {

        // Fixes issue with blank BurpKitty tabs
        if (Thread.currentThread().getContextClassLoader() == null) {
            System.err.println("Warning: context class loader for JFX thread returned null.");
            Thread.currentThread().setContextClassLoader(ClassLoader.getSystemClassLoader());
        }

        createMasterPane();
        createDetailPane();
        masterDetailPane = new CollapsibleSplitPane(masterPane, detailPane);
        masterDetailPane.setOrientation(Orientation.VERTICAL);
        masterDetailPane.expandedProperty().bind(isDetailNodeVisible);

        scene = new Scene(masterDetailPane);

        setScene(scene);
    }

    private void createDetailPane() {
        detailPane = new TabPane();

        javaScriptConsoleTab = new JavaScriptConsoleTab(webEngine);
        addErrorListener(javaScriptConsoleTab::handleError);
        addAlertListener(javaScriptConsoleTab::handleAlert);

        crossSiteScriptingTrackerTab = new CrossSiteScriptingTrackerTab(webEngine);
        addAlertListener(crossSiteScriptingTrackerTab::handleAlert);

        pageResourcesTab = new PageResourcesTab(webEngine);

        Tab javaScriptEditorTab = new Tab("BurpScript IDE");
        javaScriptEditorTab.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue)
                masterDetailPane.setDividerPositions(0.5);
        });
        JavaScriptEditor javaScriptEditor = new JavaScriptEditor(webEngine, controller, false);
        javaScriptEditor.setJavaScriptConsoleTab(javaScriptConsoleTab);
        javaScriptEditorTab.setContent(javaScriptEditor);

        Tab trafficBrowserTab = new Tab("Network");
        trafficBrowser = new TrafficBrowser();
        trafficBrowserTab.setContent(trafficBrowser);

        Debugger debugger = webEngine.impl_getDebugger();
        debugger.setEnabled(true);
        debugger.sendMessage("{\"id\": 1, \"method\":\"Network.enable\"}");
        debugger.setMessageCallback(new Callback<String, Void>() {

            ConcurrentHashMap<String, Traffic> trafficState = new ConcurrentHashMap<>();

            @Override
            public Void call(String param) {
                JsonParser parser = new JsonParser();
                JsonObject object = parser.parse(param).getAsJsonObject();

                String method = object.get("method").getAsString();
                JsonObject params = object.getAsJsonObject("params");
                JsonObject request = params.getAsJsonObject("request");
                JsonObject response = params.getAsJsonObject("response");
                String requestId = params.get("requestId").getAsString();

                Instant timeStamp;
                JsonElement epochObject = params.get("timestamp");
                if (epochObject != null) {
                    double epoch = epochObject.getAsDouble();
                    timeStamp = Instant.ofEpochSecond(
                            (long) Math.floor(epoch),
                            (long) (epoch * 1000000000 % 1000000000)
                    );
                } else {
                    timeStamp = Instant.now();
                }

                Traffic traffic = null;

                switch (method) {
                    case "Network.requestWillBeSent":
                        URL url = null;
                        String urlString = request.get("url").getAsString();

                        try {
                            url = new URL(urlString);
                        } catch (MalformedURLException e) {
//                            e.printStackTrace();
                        }
                        trafficState.put(
                                requestId,
                                new Traffic(
                                        (url == null) ? urlString : url.getFile(),
                                        timeStamp,
                                        (url == null) ? "" : url.getHost(),
                                        request.get("method").getAsString(),
                                        params.get("documentURL").getAsString()
                                )
                        );
                        break;
                    case "Network.responseReceived":
                        traffic = trafficState.get(requestId);
                        JsonObject headers = response.getAsJsonObject("headers");
                        JsonElement contentType = headers.get("Content-Type");
                        JsonElement contentLength = headers.get("Content-Length");
                        traffic.setType((contentType == null) ? "" : contentType.getAsString());
                        JsonElement requestLine = headers.get("");
                        if (requestLine != null) {
                            String[] requestLineParts = requestLine.getAsString().split(" ", 3);
                            traffic.setStatusCode(new Integer(requestLineParts[1]));
                            traffic.setStatusText(requestLineParts[2]);
                            traffic.setSize((contentLength == null) ? "" : contentLength.getAsString());
                        } else {
                            traffic.setStatusCode(200);
                            traffic.setStatusText("OK");
                            traffic.setSize("");
                        }
                        break;
                    case "Network.loadingFinished":
                        traffic = trafficState.get(requestId);
                        traffic.setEndTime(timeStamp);
                        trafficBrowser.getTraffic().add(traffic);
                        trafficState.remove(requestId);
                        if (traffic.getEndTime().isAfter(trafficBrowser.getEndTime())) {
                            trafficBrowser.setEndTime(traffic.getEndTime());
                        }
                }
                return null;
            }
        });

        detailPane.getTabs().addAll(
                javaScriptConsoleTab,
                crossSiteScriptingTrackerTab,
                pageResourcesTab,
                trafficBrowserTab,
                javaScriptEditorTab
//                new ImagesTab(webEngine)
        );

        detailPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
    }

    private void createMasterPane() {
        webView = new WebView();

        webViewAnchorPane = new AnchorPane(webView);
        AnchorPane.setBottomAnchor(webView, 0.0);
        AnchorPane.setTopAnchor(webView, 0.0);
        AnchorPane.setLeftAnchor(webView, 0.0);
        AnchorPane.setRightAnchor(webView, 0.0);

        webEngine = webView.getEngine();

        dialog = Dialogs.create()
                .lightweight()
                .modal()
                .owner(webView);

//        locals = new LocalJSObject(webEngine);
//        globals = GlobalJSObject.getGlobalJSObject(webEngine);
        javaScriptHelpers = new BurpKitBridge(webEngine);
        originalUserAgent = webEngine.getUserAgent();
        webEngine.setJavaScriptEnabled(true);
        webEngine.setOnAlert(this::handleAlert);
        webEngine.setOnError(this::handleError);
        webEngine.setConfirmHandler(param -> true);
        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);

        createToolBar();

        createStatusBar();

        webEngine.load("about:blank");

        masterPane = new BorderPane();
        masterPane.setTop(toolBar);
        masterPane.setCenter(webViewAnchorPane);
        masterPane.setBottom(statusBar);

    }

    private void createStatusBar() {
        statusBar = new StatusBar();
        statusBar.setText("Alerts");

        Button alertsButton = new Button();
        alertsButton.textProperty().bind(numberOfAlerts);
        alertsButton.setBackground(new Background(new BackgroundFill(Color.ORANGE, new CornerRadii(2), new Insets(4))));
        alertsButton.setOnAction(event -> {
            isDetailNodeVisible.setValue(true);
            detailPane.getSelectionModel().select(0);
        });

        statusBar.getLeftItems().add(alertsButton);
        statusBar.progressProperty().bind(webEngine.getLoadWorker().progressProperty());
    }

    private void createToolBar() {
        createUrlTextField();
        createShowConsoleButton();
        createShowAlertsButton();
        createFirebugButton();
        createScreenShotButton();

        toolBar = new ToolBar();

        toolBar.getItems().addAll(
                urlTextField,
                consoleToggleButton,
                showAlertsToggleButton,
                firebugButton,
                screenShotButton
        );
    }

    private void createUrlTextField() {
        urlTextField = new WebURLField(webEngine);
        urlTextField.setEditable(enabled);
        HBox.setHgrow(urlTextField, Priority.ALWAYS);
    }

    private void createShowConsoleButton() {
        consoleToggleButton = new ToggleButton(FontAwesome.ICON_TERMINAL);
        consoleToggleButton.setFont(Font.font("FontAwesome", 14));
        consoleToggleButton.setTextFill(Color.DARKBLUE);
        consoleToggleButton.setTooltip(new Tooltip("Show/Hide Console."));
        consoleToggleButton.selectedProperty().bindBidirectional(isDetailNodeVisible);
    }

    private void createShowAlertsButton() {
        showAlertsToggleButton = new ToggleButton(FontAwesome.ICON_WARNING);
        showAlertsToggleButton.setFont(Font.font("FontAwesome", 14));
        showAlertsToggleButton.setTextFill(Color.DARKGOLDENROD);
        showAlertsToggleButton.setTooltip(new Tooltip("Show/Hide Alerts."));
        showAlertsToggleButton.selectedProperty().bindBidirectional(showAlerts);
    }

    private void createScreenShotButton() {
        screenShotButton = new Button(FontAwesome.ICON_CAMERA);
        screenShotButton.setFont(Font.font("FontAwesome", 14));
        screenShotButton.setTooltip(new Tooltip("Take Screen Shot."));
//        screenShotButton.disableProperty().bind(webEngine.getLoadWorker().runningProperty());
        screenShotButton.setOnAction(observable -> {
            WritableImage image = masterPane.snapshot(null, null);
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss'.png'");

            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Screen Shot...");
            fileChooser.setInitialFileName(simpleDateFormat.format(Date.from(Instant.now())));
            File imageFile = fileChooser.showSaveDialog(null);

            if (imageFile != null) {
                try {
                    ImageIO.write(SwingFXUtils.fromFXImage(image, null), "png", imageFile);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void createFirebugButton() {
        firebugButton = new Button(FontAwesome.ICON_BUG);
        firebugButton.setFont(Font.font("FontAwesome", 14));
        firebugButton.setTextFill(Color.RED);
        firebugButton.setTooltip(new Tooltip("Launch Firebug."));
        firebugButton.disableProperty().bind(webEngine.getLoadWorker().runningProperty());
        firebugButton.setOnAction(observable -> webEngine.executeScript(firebugScript));
    }

    private void handleError(WebErrorEvent event) {
        for (EventHandler<WebErrorEvent> handler : errorListeners)
            handler.handle(event);
    }

    public void addAlertListener(EventHandler<WebEvent<String>> handler) {
        if (!alertListeners.contains(handler))
            alertListeners.add(handler);
    }

    public void removeAlertListener(EventHandler<WebEvent<String>> handler) {
        if (alertListeners.contains(handler))
            alertListeners.remove(handler);
    }

    public void addErrorListener(EventHandler<WebErrorEvent> handler) {
        if (!errorListeners.contains(handler))
            errorListeners.add(handler);
    }

    public void removeErrorListener(EventHandler<WebErrorEvent> handler) {
        if (errorListeners.contains(handler))
            errorListeners.remove(handler);
    }

    private void handleAlert(WebEvent<String> event) {
        numberOfAlerts.setValue(Integer.toString(Integer.valueOf(numberOfAlerts.getValue()) + 1));
        String message = event.getData();

        /*
         * Handle all the external onAlert event handlers first.
         */
        for (EventHandler<WebEvent<String>> handler : alertListeners)
            handler.handle(event);

        /*
         * Finally display an alert box if the operator demands it.
         */
        if (showAlerts.getValue()) {
            dialog.title("JavaScript Alert")
                    .message(message)
                    .showInformation();
            resetParents();
        }

    }

    /**
     * Used to get rid of LightweightDialog parent container which causes ugly GUI glitches.
     * Called after every time a dialog window is closed.
     */
    private void resetParents() {
        Parent webViewParent = webView.getParent();
        webViewAnchorPane.getChildren().remove(webViewParent);
        webViewAnchorPane.getChildren().add(webView);
    }

    public void loadUrl(final String url) {
        Platform.runLater(() -> webEngine.load(url));
    }

    public void loadUrl(final String url, final String userAgent) {
        Platform.runLater(() -> {
            webEngine.setUserAgent(originalUserAgent + userAgent);
            webEngine.load(url);
            webEngine.setUserAgent(originalUserAgent);
        });
    }

    public void loadContent(final String content) {
        Platform.runLater(() -> webEngine.loadContent(content));
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.READY || newValue == Worker.State.SCHEDULED) {
            if (trafficBrowser != null) {
                trafficBrowser.setStartTime(Instant.now());
                trafficBrowser.getTraffic().clear();
            }
            numberOfAlerts.setValue("0");
        } else if (newValue == Worker.State.SUCCEEDED) {
            JSObject result = (JSObject) webEngine.executeScript("window");

            result.setMember(
                    "burpCallbacks",
                    new BurpExtenderCallbacksBridge(webEngine, BurpExtender.getBurpExtenderCallbacks())
            );

            result.setMember(
                    "burpKit",
                    javaScriptHelpers
            );

//            result.setMember("locals", locals);
//
//            result.setMember("globals", globals);

            if (controller != null) {
                result.setMember(
                        "burpController",
                        controller
                );
            }
        } else if (newValue == Worker.State.FAILED) {
            dialog.title("Navigation Failed")
                    .message(webEngine.getLoadWorker().getException().getMessage())
                    .showInformation();
            resetParents();
        } else if (newValue == Worker.State.CANCELLED) {
            dialog.title("Navigation Cancelled")
                    .message(webEngine.getLoadWorker().getMessage())
                    .showInformation();
            resetParents();
        }


    }

//    public void logRequest(final URL url) {
//        Platform.runLater(new Runnable() {
//            @Override
//            public void run() {
//                networkRequestsListView.getItems().add(url.toString());
//            }
//        });
//    }


}

