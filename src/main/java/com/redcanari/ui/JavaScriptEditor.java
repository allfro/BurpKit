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
import com.redcanari.js.BurpExtenderCallbacksBridge;
import com.redcanari.js.JavaScriptHelpers;
import com.redcanari.ui.font.FontAwesome;
import com.redcanari.ui.providers.JSAutoCompletionProvider;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker;
import javafx.geometry.Orientation;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.text.Font;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.FileChooser;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;
import org.controlsfx.control.StatusBar;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * Created by ndouba on 15-06-16.
 */
public class JavaScriptEditor extends BorderPane {

    private final WebView webView;
    private final WebEngine webEngine;
    private final StatusBar statusBar = new StatusBar();
    private final ToggleButton onLoadCheckbox;
    private final IMessageEditorController controller;
    private JavaScriptConsoleTab javaScriptConsoleTab = null;
    private final boolean showConsole;
//    private LocalJSObject locals;
//    private LocalJSObject globals;
    private JavaScriptHelpers javaScriptHelpers;
    private File scriptFile = null;
    private final AutoCompleteCodeArea codeArea;



    public JavaScriptEditor() {
        this(null, null, true);
    }

    public JavaScriptEditor(WebEngine webEngine) {
        this(webEngine, null, true);
    }

    public JavaScriptEditor(WebEngine webEngine, boolean showConsole) {
        this(webEngine, null, showConsole);
    }

    public JavaScriptEditor(WebEngine webEngine, IMessageEditorController controller, boolean showConsole) {
        if (webEngine == null) {
            webView = new WebView();
            webView.setPrefSize(800, 600);
            this.webEngine = webView.getEngine();
        } else {
            this.webEngine = webEngine;
            webView = null;
        }
//        locals = new LocalJSObject(this.webEngine);
//        globals = GlobalJSObject.getGlobalJSObject(this.webEngine);
        javaScriptHelpers = new JavaScriptHelpers(this.webEngine);
        this.codeArea = new AutoCompleteCodeArea(new JSAutoCompletionProvider(this.webEngine));
        this.controller = controller;
        this.showConsole = showConsole;

        onLoadCheckbox = new ToggleButton(FontAwesome.ICON_REFRESH);
        onLoadCheckbox.setFont(Font.font("FontAwesome", 14));
        onLoadCheckbox.setStyle("-fx-text-fill: firebrick");
        onLoadCheckbox.setTooltip(new Tooltip("Run script when document.onload event is triggered."));

        init();

        if (showConsole) {
            this.webEngine.load("about:blank");
        }
    }

    private void init() {
        setTop(createMenuBar());
        setCenter(createContentPane());
        setBottom(createStatusBar());
        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);
    }

    private Node createContentPane() {
        if (showConsole) {
            SplitPane splitPane = new SplitPane();
            splitPane.setOrientation(Orientation.VERTICAL);
            TabPane tabPane = new TabPane();
            tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
            javaScriptConsoleTab = new JavaScriptConsoleTab(webEngine);
            webEngine.setOnAlert(javaScriptConsoleTab::handleAlert);
            webEngine.setOnError(javaScriptConsoleTab::handleError);

            Tab webViewTab = new Tab("Web View");
            webViewTab.setContent(this.webView);

            tabPane.getTabs().addAll(javaScriptConsoleTab, webViewTab);
            splitPane.getItems().addAll(codeArea, tabPane);
            splitPane.setDividerPositions(0.8, 0.2);
            return splitPane;
        }
        return codeArea;
    }

    private Node createStatusBar() {
        statusBar.setText("untitled.js*");
        statusBar.getRightItems().addAll(onLoadCheckbox);
        return statusBar;
    }

    private Node createMenuBar() {
        ToolBar toolBar = new ToolBar();

        Button runButton = new Button(FontAwesome.ICON_PLAY);
        runButton.setFont(Font.font("FontAwesome", 14));
        runButton.setStyle("-fx-text-fill: green;");
        runButton.setTooltip(new Tooltip("Run Script"));

        runButton.setOnMouseClicked(event -> {
            try {
                webEngine.executeScript(codeArea.getText());
            } catch (JSException e) {
                if (javaScriptConsoleTab != null)
                    javaScriptConsoleTab.printException(e);
            }
        });

        Button openButton = new Button(FontAwesome.ICON_FOLDER_OPEN);
        openButton.setFont(Font.font("FontAwesome", 14));
        openButton.setStyle("-fx-text-fill: goldenrod;");
        openButton.setTooltip(new Tooltip("Load Script"));

        openButton.setOnMouseClicked(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Load Script...");
            fileChooser.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("JavaScript files (*.js)", "*.js"),
                    new FileChooser.ExtensionFilter("All files (*.*)", "*.*")
            );
            scriptFile = fileChooser.showOpenDialog(getScene().getWindow());
            if (scriptFile != null) {
                try {
                    codeArea.clear();
                    codeArea.replaceText(String.join("\n", Files.readAllLines(scriptFile.toPath())));
                    statusBar.setText(scriptFile.getName());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        Button saveButton = new Button(FontAwesome.ICON_FLOPPY_O);
        saveButton.setFont(Font.font("FontAwesome", 14));
        saveButton.setStyle("-fx-text-fill: darkblue;");
        saveButton.setTooltip(new Tooltip("Load Script"));

        saveButton.setOnMouseClicked(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Script...");
            fileChooser.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("JavaScript files (*.js)", "*.js"),
                    new FileChooser.ExtensionFilter("All files (*.*)", "*.*")
            );
            if (scriptFile == null)
                scriptFile = fileChooser.showSaveDialog(getScene().getWindow());
            if (scriptFile != null) {
                try {
                    Files.write(scriptFile.toPath(), codeArea.getText().getBytes());
                    statusBar.setText(scriptFile.getName());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        Button newButton = new Button(FontAwesome.ICON_FILE);
        newButton.setFont(Font.font("FontAwesome", 14));
        newButton.setStyle("-fx-text-fill: white;");
        newButton.setTooltip(new Tooltip("New Script"));

        newButton.setOnMouseClicked(event -> {
            codeArea.clear();
            scriptFile = null;
            statusBar.setText("untitled.js*");
        });

        toolBar.getItems().addAll(
                runButton,
                openButton,
                saveButton,
                newButton
        );
        return toolBar;
    }

    public void setJavaScriptConsoleTab(JavaScriptConsoleTab javaScriptConsoleTab) {
        this.javaScriptConsoleTab = javaScriptConsoleTab;
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.SUCCEEDED) {
            // We assume that if we are showing the console that means that we have to manually set our burp helpers
            // Otherwise, this is already being used as part of a burp controller and we don't touch the JS namespace.
            if (showConsole) {
                JSObject result = (JSObject) webEngine.executeScript("window");

                result.setMember(
                        "burpCallbacks",
                        new BurpExtenderCallbacksBridge(webEngine, BurpExtender.getBurpExtenderCallbacks())
                );

                result.setMember(
                        "burpKit",
                        javaScriptHelpers
                );

//                result.setMember("locals", locals);
//
//                result.setMember("globals", globals);

                // Sometimes this control will not appear as part of a burp message editor so we don't need to add it to
                // the JS namespace.
                if (controller != null) {
                    result.setMember(
                            "burpController",
                            controller
                    );
                }
            }
            // Only execute the user's script if our checkbox is checked.
            if (onLoadCheckbox.isSelected())
                webEngine.executeScript(codeArea.getText());
        }
    }
}
