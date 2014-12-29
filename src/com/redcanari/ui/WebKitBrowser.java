package com.redcanari.ui;

import burp.BurpExtender;
import burp.IMessageEditorController;
import com.redcanari.js.BurpExtenderCallbacksBridge;
import javafx.application.Platform;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
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
import java.lang.reflect.Field;
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
    private BorderPane borderPane;
    private TextField urlTextField;
    private TabPane tabPane;
    private boolean enabled = false;

    private PageResourcesTab pageResourcesTab;
    private JavaScriptConsoleTab javaScriptConsoleTab;
    private CrossSiteScriptingTrackerTab crossSiteScriptingTrackerTab;

    private final StringProperty numberOfAlerts = new SimpleStringProperty("0");
    private final SimpleBooleanProperty showAlerts = new SimpleBooleanProperty(false);

    private final BooleanProperty isDetailNodeVisible = new SimpleBooleanProperty(true);
    private final List<EventHandler<WebEvent<String>>> alertListeners = new ArrayList<>();
    private final List<EventHandler<WebErrorEvent>> errorListeners = new ArrayList<>();

    public WebKitBrowser() {
        init();
    }

    public WebKitBrowser(boolean enabled) {
        this.enabled = enabled;
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
        masterDetailPane.setMasterNode(borderPane);
        masterDetailPane.setDetailNode(tabPane);
        masterDetailPane.setDetailSide(Side.BOTTOM);
        masterDetailPane.setShowDetailNode(true);
        masterDetailPane.setAnimated(true);
        masterDetailPane.showDetailNodeProperty().bind(isDetailNodeVisible);

        scene = new Scene(masterDetailPane);
        setScene(scene);
    }

    private void createDetailPane() {
        tabPane = new TabPane();

        javaScriptConsoleTab = new JavaScriptConsoleTab(webEngine);
        addErrorListener(javaScriptConsoleTab::handleError);
        addAlertListener(javaScriptConsoleTab::handleAlert);

        crossSiteScriptingTrackerTab = new CrossSiteScriptingTrackerTab(webEngine);
        addAlertListener(crossSiteScriptingTrackerTab::handleAlert);

        pageResourcesTab = new PageResourcesTab(webEngine);

        tabPane.getTabs().addAll(
                javaScriptConsoleTab,
                crossSiteScriptingTrackerTab,
                pageResourcesTab
        );

        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
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

//        webEngine.load("about:blank");

        borderPane = new BorderPane();
        borderPane.setTop(toolBar);
        borderPane.setCenter(webViewAnchorPane);
        borderPane.setBottom(statusBar);
    }

    private void createStatusBar() {
        statusBar = new StatusBar();
        statusBar.setText("Alerts");

        Button alertsButton = new Button();
        alertsButton.textProperty().bind(numberOfAlerts);
        alertsButton.setBackground(new Background(new BackgroundFill(Color.ORANGE, new CornerRadii(2), new Insets(4))));
        alertsButton.setOnAction(event -> {
            isDetailNodeVisible.setValue(true);
            tabPane.getSelectionModel().select(0);
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
        urlTextField = new TextField();
        if (enabled)
            urlTextField.setOnAction(event -> {
                String url = urlTextField.getText();
                if (!url.matches("^(https?|ftp|about|javascript|data|file|telnet):(//)?.*"))
                    url = "http://" + url;
                loadUrl(url);
            });
        else
            urlTextField.textProperty().bind(webEngine.locationProperty());

        HBox.setHgrow(urlTextField, Priority.ALWAYS);
    }

    private void createShowConsoleButton() {
        consoleToggleButton = new ToggleButton("Console");
        consoleToggleButton.selectedProperty().bindBidirectional(isDetailNodeVisible);
    }

    private void createShowAlertsButton() {
        showAlertsToggleButton = new ToggleButton("Show Alerts");
        showAlertsToggleButton.selectedProperty().bindBidirectional(showAlerts);
    }

    private void createScreenShotButton() {
        screenShotButton = new Button("Screen Shot");
        screenShotButton.disableProperty().bind(webEngine.getLoadWorker().runningProperty());
        screenShotButton.setOnAction(observable -> {
            WritableImage image = borderPane.snapshot(null, null);
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
        firebugButton = new Button("Launch Firebug");
        firebugButton.disableProperty().bind(webEngine.getLoadWorker().runningProperty());
        firebugButton.setOnAction(observable -> webEngine.executeScript(
                "(function(F,i,r,e,b,u,g,L,I,T,E) {" +
                        "if(F.getElementById(b))" +
                        "return;" +
                        "E=F[i+'NS']&&F.documentElement.namespaceURI;" +
                        "E=E?F[i+'NS'](E,'script'):F[i]('script');" +
                        "E[r]('id',b);E[r]('src',I+g+T);" +
                        "E[r](b,u);(F[e]('head')[0]||F[e]('body')[0]).appendChild(E);" +
                        "E=new Image;E[r]('src',I+L);" +
                        "})(" +
                        "document," +
                        "'createElement'," +
                        "'setAttribute'," +
                        "'getElementsByTagName'," +
                        "'FirebugLite'," +
                        "'4'," +
                        "'firebug-lite.js'," +
                        "'releases/lite/latest/skin/xp/sprite.png'," +
                        "'https://getfirebug.com/'," +
                        "'#startOpened'" +
                        ");"
        ));
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

        if (showAlerts.getValue()) {
            Dialogs.create()
                    .lightweight()
                    .owner(webView)
                    .title("JavaScript Alert")
                    .message(message)
                    .showInformation();
        }

        for (EventHandler<WebEvent<String>> handler : alertListeners)
            handler.handle(event);
    }

    /*
     * Hot patch removeNotify() to set scaleFactor=1 in order to get rid of graphics glitches in Mac OS X and possibly
     * other systems with high resolution displays. Refer to http://cr.openjdk.java.net/~ant/RT-38915/webrev.0/ for
     * relevant patch details.
     */
    @Override
    public void removeNotify() {

        try {

            Field scaleFactor = JFXPanel.class.getDeclaredField("scaleFactor");
            scaleFactor.setAccessible(true);
            scaleFactor.setInt(this, 1);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }

        super.removeNotify();
    }

    public void loadUrl(final String url) {
        Platform.runLater(() -> {
            javaScriptConsoleTab.clear();
            crossSiteScriptingTrackerTab.clear();
            webEngine.load(url);
        });
    }

    public void loadContent(final String content) {
        Platform.runLater(() -> {
            webEngine.loadContent(content);
        });
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.READY || newValue == Worker.State.SCHEDULED) {
            if (enabled)
                urlTextField.textProperty().bind(webEngine.locationProperty());
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

            if (enabled)
                urlTextField.textProperty().unbind();
        } else if (newValue == Worker.State.FAILED) {
            Dialogs.create()
                    .lightweight()
                    .owner(webView)
                    .title("Navigation Failed")
                    .message(webEngine.getLoadWorker().getException().getMessage())
                    .showInformation();
            if (enabled)
                urlTextField.textProperty().unbind();
        } else if (newValue == Worker.State.CANCELLED) {
            Dialogs.create()
                    .lightweight()
                    .owner(webView)
                    .title("Navigation Cancelled")
                    .message(webEngine.getLoadWorker().getMessage())
                    .showInformation();
            if (enabled)
                urlTextField.textProperty().unbind();
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

