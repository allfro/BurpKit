package com.redcanari.ui;

import burp.BurpExtender;
import burp.IMessageEditorController;
import com.redcanari.js.BurpExtenderCallbacksBridge;
import com.redcanari.ui.font.FontAwesome;
import com.redcanari.util.ResourceUtils;
import javafx.application.Platform;
import javafx.beans.Observable;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker;
import javafx.embed.swing.JFXPanel;
import javafx.embed.swing.SwingFXUtils;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Side;
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
import netscape.javascript.JSObject;
import org.controlsfx.control.MasterDetailPane;
import org.controlsfx.control.StatusBar;
import org.controlsfx.dialog.Dialogs;

import javax.imageio.ImageIO;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Created by ndouba on 2014-06-01.
 */
public class WebKitBrowser extends JFXPanel {

    private WebEngine webEngine;
    private WebView webView;
    private Scene scene;
    private IMessageEditorController controller;
    private MasterDetailPane masterDetailPane;
    private ToolBar toolBar;
    private StatusBar statusBar;
    private Button firebugButton;
    private ToggleButton consoleToggleButton;
    private ToggleButton showAlertsToggleButton;
    private AnchorPane webViewAnchorPane;
    private Button screenShotButton;
    private BorderPane masterPane;
    private WebURLField urlTextField;
    private TabPane detailPane;
    private boolean enabled = false;

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
        createMasterPane();
        createDetailPane();

        masterDetailPane = new MasterDetailPane();
        masterDetailPane.setMasterNode(masterPane);
        masterDetailPane.setDetailNode(detailPane);
        masterDetailPane.setDetailSide(Side.BOTTOM);
        masterDetailPane.setShowDetailNode(true);
        masterDetailPane.setAnimated(true);
        masterDetailPane.showDetailNodeProperty().bind(isDetailNodeVisible);

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

        detailPane.getTabs().addAll(
                javaScriptConsoleTab,
                crossSiteScriptingTrackerTab,
                pageResourcesTab
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

    private void handleAlert(Observable observable) {

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
        screenShotButton.disableProperty().bind(webEngine.getLoadWorker().runningProperty());
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
            Dialogs.create()
                    .lightweight()
                    .modal()
                    .owner(webView)
                    .title("JavaScript Alert")
                    .message(message)
                    .showInformation();
        }

    }

    /*
     * Hot patch removeNotify() to set scaleFactor=1 in order to get rid of graphics glitches in Mac OS X and possibly
     * other systems with high resolution displays. Refer to http://cr.openjdk.java.net/~ant/RT-38915/webrev.0/ for
     * relevant patch details.
     */
//    @Override
//    public void removeNotify() {
//
//        try {
//
//            Field scaleFactor = JFXPanel.class.getDeclaredField("scaleFactor");
//            scaleFactor.setAccessible(true);
//            scaleFactor.setInt(this, 1);
//        } catch (NoSuchFieldException | IllegalAccessException e) {
//            e.printStackTrace();
//        }
//
//        super.removeNotify();
//    }

    public void loadUrl(final String url) {
        Platform.runLater(() -> webEngine.load(url));
    }

    public void loadContent(final String content) {
        Platform.runLater(() -> webEngine.loadContent(content));
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.READY || newValue == Worker.State.SCHEDULED) {
            numberOfAlerts.setValue("0");
        } else if (newValue == Worker.State.SUCCEEDED) {
            JSObject result = (JSObject) webEngine.executeScript("window");

            result.setMember(
                    "bec",
//                    "burpExtenderCallbacks",
                    new BurpExtenderCallbacksBridge(webEngine, BurpExtender.getBurpExtenderCallbacks())
            );

            result.setMember(
                    "burpController",
                    controller
            );
        } else if (newValue == Worker.State.FAILED) {
            Dialogs.create()
                    .lightweight()
                    .owner(webView)
                    .title("Navigation Failed")
                    .message(webEngine.getLoadWorker().getException().getMessage())
                    .showInformation();
        } else if (newValue == Worker.State.CANCELLED) {
            Dialogs.create()
                    .lightweight()
                    .owner(webView)
                    .title("Navigation Cancelled")
                    .message(webEngine.getLoadWorker().getMessage())
                    .showInformation();
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

