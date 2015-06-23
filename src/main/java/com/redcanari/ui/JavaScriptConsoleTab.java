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

import com.redcanari.ui.providers.JSAutoCompletionProvider;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Worker;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebErrorEvent;
import javafx.scene.web.WebEvent;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;
import org.controlsfx.control.textfield.AutoCompletionBinding;


/**
 * Created by ndouba on 14-12-16.
 */
public class JavaScriptConsoleTab extends Tab {

    private final ListView<Object> javaScriptListView = new ListView<>();
    private ObservableList<Object> dataSource = FXCollections.observableArrayList();
    private final WebEngine webEngine;
    private final AutoCompleteTextField textField;

    public JavaScriptConsoleTab(WebEngine webEngine) {
        super("JavaScript Console");

        this.webEngine = webEngine;
        this.textField = new AutoCompleteTextField(new JSAutoCompletionProvider(webEngine));

        init();

    }

    private void init() {

        this.webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);

        createListView();


        VBox vbox = new VBox();
        vbox.getChildren().addAll(javaScriptListView, createTextField());

        setContent(vbox);

    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.SCHEDULED)
            clear();
    }

    private Node createTextField() {
        StackPane stackPane = new StackPane();

        textField.setPromptText("execute command...");
        textField.setStyle("-fx-font-family: monospace; -fx-padding: 0.25em 0.416667em  0.333333em 3em");


        textField.setOnAction(event -> {
            String script = textField.getText();
            textField.clear();

            if (script.isEmpty())
                return;

            javaScriptListView.getItems().add(new JSCommand(script));

            try {
                Object result = webEngine.executeScript(script);
                javaScriptListView.getItems().add(result);
            } catch (JSException e) {
                javaScriptListView.getItems().add(new JSError(e.getMessage()));
            }

        });
        HBox.setHgrow(textField, Priority.ALWAYS);
        StackPane.setAlignment(textField, Pos.CENTER);

        Label promptLabel = new Label(">>>");
        promptLabel.setTextFill(Color.BLUE);
        promptLabel.setBackground(Background.EMPTY);
        promptLabel.setFont(Font.font("monospaced"));
        promptLabel.setPadding(new Insets(5, 5, 5, 5));
        StackPane.setAlignment(promptLabel, Pos.CENTER_LEFT);

        stackPane.getChildren().addAll(textField, promptLabel);
        return stackPane;
    }

    private void createListView() {
//        javaScriptListView.getStylesheets().add();
        javaScriptListView.setCellFactory(param -> new ConsoleListCell());
        javaScriptListView.setItems(dataSource);
        FXUtils.addAutoScroll(javaScriptListView);
        VBox.setVgrow(javaScriptListView, Priority.ALWAYS);
    }

    public void clear() {
        if (!dataSource.isEmpty()) {
            javaScriptListView.scrollTo(0);
            dataSource.clear();
        }
    }

    public void handleError(WebErrorEvent event) {
        printError(event.getMessage());
    }

    public void handleAlert(WebEvent<String> event) {
        printAlert(event.getData());
    }

    public void printError(String message) {
        dataSource.add(new JSError("error('" + message.replace("'", "\\'") + "')"));
    }

    public void printException(Exception exception) {
        dataSource.add(new JSError(exception.getMessage()));
    }

    public void printAlert(String message) {
        dataSource.add(new JSAlert(message));
    }

    public void log(String message) {
        dataSource.add(message);
    }

    public class ConsoleMessage {
        protected final String message;

        public ConsoleMessage(String message) {
            this.message = message;
        }

        public String toString() {
            return message;
        }
    }

    public class JSCommand extends ConsoleMessage {

        public JSCommand(String message) {
            super(message);
        }

        public String getCommand() {
            return message;
        }

        public String toString() {
            return ">>> " + message;
        }
    }

    public class JSError extends ConsoleMessage {
        public JSError(String message) {
            super(message);
        }
    }

    public class JSAlert extends ConsoleMessage {

        public JSAlert(String message) {
            super(message);
        }

        public String toString() {
            return "ALERT: " + message;
        }
    }

    public class JSString extends ConsoleMessage {

        public JSString(String message) {
            super(message);
        }

        public String toString() {
            return "'" + message.replace("'", "\\'") + "'";
        }
    }

    protected class ConsoleListCell extends ListCell<Object> {
        private String lastAppliedStyle = null;

        @Override
        protected void updateItem(Object item, boolean empty) {
            super.updateItem(item, empty);

            if (empty || item == null) {
                setText(null);
                setGraphic(null);
            } else {
                if (lastAppliedStyle != null) {
                    getStyleClass().remove(lastAppliedStyle);
                    lastAppliedStyle = null;
                }

                if (item instanceof JSObject) {
                    lastAppliedStyle = item.toString().startsWith("[object ")?"jsobject":"jsfunction";
                } else if (item instanceof Integer || item instanceof Double) {
                    lastAppliedStyle = "jsnumber";
                } else if (item instanceof JSCommand) {
                    lastAppliedStyle = "jscommand";
                } else if (item instanceof JSError) {
                    lastAppliedStyle = "jserror";
                } else if (item instanceof String) {
                    String string = (String) item;
                    if (string.equals("undefined")) {
                        lastAppliedStyle = "jsundefined";
                    } else {
                        item = new JSString(string);
                        lastAppliedStyle = "jsstring";
                    }
                } else {
                    lastAppliedStyle = "jsunknown";
                }

                if (isSelected())
                    lastAppliedStyle = null;
                else
                    getStyleClass().add(lastAppliedStyle);
                setText(item.toString());
            }
        }

        @Override
        public void updateSelected(boolean selected) {
            if (selected && lastAppliedStyle != null)
                getStyleClass().remove(lastAppliedStyle);
            else
                getStyleClass().add(lastAppliedStyle);
            super.updateSelected(selected);
        }

        @Override
        public String getUserAgentStylesheet() {
            return getClass().getResource("/stylesheets/jslistview.css").toExternalForm();
        }
    }


}
