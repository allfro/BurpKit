package com.redcanari.ui;

import com.redcanari.burp.WebKitBrowserTab;
import com.redcanari.tainter.Tainter;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.*;
import javafx.embed.swing.JFXPanel;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Orientation;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.TextFlow;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebErrorEvent;
import javafx.scene.web.WebEvent;
import javafx.scene.web.WebView;
import javafx.util.Callback;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;

import javax.swing.*;
import java.net.URL;
import java.util.*;

/**
 * Created by ndouba on 2014-06-01.
 */
public class WebKitBrowser extends JFXPanel {

    private WebEngine webEngine = null;
    private ListView<String> javascriptListView = null;
    private TextField textField = null;
    private TreeItem<String> root = null;
    private Tainter tainter = Tainter.getInstance();
    private ObservableMap<String, ObservableSet<String>> dataSource = null;

    public WebKitBrowser() {
        init();
    }

    private void init() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Platform.setImplicitExit(false);
                Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        createScene();
                    }
                });
            }
        });
    }

    private void addTab(TabPane tabPane, String title, Node node) {
        Tab tab = new Tab(title);
        tab.setContent(node);
        tab.setClosable(false);
        tabPane.getTabs().add(tab);
    }

    private void createScene() {
        WebView webView = new WebView();
        SplitPane splitPane = new SplitPane();
        TreeView<String> treeView = new TreeView<String>();
        root = new TreeItem<String>("Detected Taints", new ImageView(new Image(getClass().getResourceAsStream("/resource/images/world.png"))));
        root.setExpanded(true);
        treeView.setRoot(root);

        final Image fireImage = new Image(getClass().getResourceAsStream("/resource/images/element_fire.png"));


        dataSource = FXCollections.observableMap(new HashMap<String, ObservableSet<String>>());

        dataSource.addListener(new MapChangeListener<String, ObservableSet<String>>() {
            @Override
            public void onChanged(Change<? extends String, ? extends ObservableSet<String>> change) {

                if (!change.wasAdded())
                    return;

                String taintId = change.getKey();
                ObservableSet<String> items = change.getValueAdded();
                final TreeItem<String> treeItem = new TreeItem<String>(taintId + " (originally from: " + tainter.get(taintId) + ")", new ImageView(fireImage));

                root.getChildren().add(treeItem);

                for (String s : items) {
                    treeItem.getChildren().add(new TreeItem<String>(s, new ImageView(fireImage)));
                }

                items.addListener(new SetChangeListener<String>() {
                    @Override
                    public void onChanged(Change<? extends String> c) {
                        if (c.wasAdded())
                            treeItem.getChildren().add(new TreeItem<String>(c.getElementAdded(), new ImageView(fireImage)));
                    }
                });
            }
        });


        textField = new TextField();
        textField.setPromptText("execute command...");
        textField.setStyle("-fx-font-weight:bold;");
        textField.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (textField.getText().isEmpty())
                    return;
                try {
                    Object result = webEngine.executeScript(textField.getText());

                    javascriptListView.getItems().add("result: " + result.toString());
                }
                catch (JSException e) {
                    javascriptListView.getItems().add("exception: " + e.getMessage());
                }
                textField.clear();
            }
        });

        javascriptListView = new ListView<String>();
        javascriptListView.setStyle("-fx-font-weight:bold;");
        VBox.setVgrow(javascriptListView, Priority.ALWAYS);

        VBox vbox = new VBox();
        vbox.getChildren().addAll(javascriptListView, textField);


        TabPane tabPane = new TabPane();

        addTab(tabPane, "Javascript", vbox);
        addTab(tabPane, "Network Requests", treeView);

        webEngine = webView.getEngine();
        webEngine.setJavaScriptEnabled(true);
        webEngine.setOnAlert(new EventHandler<WebEvent<String>>() {
            @Override
            public void handle(WebEvent<String> event) {
                String message = event.getData();
                if (tainter.containsKey(message)) {
                    ObservableSet<String> urls = null;
                    if (!dataSource.containsKey(message)) {
                        urls = FXCollections.observableSet(new HashSet<String>());
                        urls.add(webEngine.getLocation().replaceFirst("&" + WebKitBrowserTab.REPEATER_PARAM_NAME + "=.+&?", "")); // Avoid triggering another event for adding one item.
                        dataSource.put(message, urls);
                    } else {
                        urls = dataSource.get(message);
                        urls.add(webEngine.getLocation().replaceFirst("&" + WebKitBrowserTab.REPEATER_PARAM_NAME + "=.+&?", ""));
                    }
                }
                javascriptListView.getItems().add("alert(): " + message);
            }
        });
        webEngine.setOnError(new EventHandler<WebErrorEvent>() {
            @Override
            public void handle(WebErrorEvent event) {
                javascriptListView.getItems().add("error(): " + event.getMessage());
            }
        });
        webEngine.setConfirmHandler(new Callback<String, Boolean>() {
            @Override
            public Boolean call(String param) {
                return true;
            }
        });

        webEngine.load("about:blank");
        splitPane.setOrientation(Orientation.VERTICAL);
        splitPane.getItems().addAll(webView, tabPane);
        Scene scene = new Scene(splitPane);
        setScene(scene);
    }

    public void loadUrl(final String url) {
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                if (!javascriptListView.getItems().isEmpty())
                    javascriptListView.getItems().clear();
//                if (!networkRequestsListView.getItems().isEmpty())
//                    networkRequestsListView.getItems().clear();
                webEngine.load(url);
            }
        });
    }

    public void loadContent(final String content) {
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                webEngine.loadContent(content);
            }
        });
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

