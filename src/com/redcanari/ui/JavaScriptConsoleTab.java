package com.redcanari.ui;

import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.paint.Paint;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebErrorEvent;
import javafx.scene.web.WebEvent;
import javafx.util.Callback;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Created by ndouba on 14-12-16.
 */
public class JavaScriptConsoleTab extends Tab {

    private final ListView<Object> javaScriptListView = new ListView<>();
    private final TextField textField = new CircularTextField();
    private final WebEngine webEngine;

    private final String BURPKIT_CONSOLE_PREFIX = "__BURPKIT_CONSOLE_PREFIX__";
    private final String BURPKIT_ERROR_PREFIX = "__BURPKIT_ERROR_PREFIX__";

    public JavaScriptConsoleTab(WebEngine webEngine) {
        super("JavaScript Console");

        this.webEngine = webEngine;
        init();
    }

    private void init() {

        createListView();
        createTextField();

        VBox vbox = new VBox();
        vbox.getChildren().addAll(javaScriptListView, textField);

        setContent(vbox);

    }

    private void createTextField() {
        textField.setPromptText("execute command...");
        textField.setStyle("-fx-font-family: monospace");

        textField.setOnAction(event -> {

            if (textField.getText().isEmpty())
                return;

            javaScriptListView.getItems().add(new JSCommand(textField.getText()));

            try {
                Object result = webEngine.executeScript(textField.getText());
                javaScriptListView.getItems().add(result);
            } catch (JSException e) {
                javaScriptListView.getItems().add(new JSError(e.getMessage()));
            }
            textField.clear();

        });
        textField.setOnMouseClicked(event -> {
            textField.selectAll();
        });
    }

    private void createListView() {

        javaScriptListView.setCellFactory(new Callback<ListView<Object>, ListCell<Object>>() {

            private final Background BACKGROUND_LIGHT_YELLOW = new Background(new BackgroundFill(Color.LIGHTGOLDENRODYELLOW, CornerRadii.EMPTY, Insets.EMPTY));

            @Override
            public ListCell<Object> call(ListView<Object> param) {
                return new ListCell<Object>() {
                    @Override
                    protected void updateItem(Object item, boolean empty) {
                        super.updateItem(item, empty);

                        if (empty || item == null) {
                            setText(null);
                            setGraphic(null);
                        } else {
                            setBackground(Background.EMPTY);
                            if (item instanceof JSObject) {
                                setTextFill(Color.GREEN);
                            } else if (item instanceof Integer || item instanceof Double) {
                                setTextFill(Color.BLACK);
                            } else if (item instanceof JSCommand) {
                                setTextFill(Color.BLUE);
                            } else if (item instanceof JSError) {
                                setTextFill(Color.RED);
                                setBackground(BACKGROUND_LIGHT_YELLOW);
                            } else if (item instanceof String && Objects.equals(item, "undefined")) {
                                setTextFill(Color.DARKGRAY);
                            } else {
                                setTextFill(Color.RED);
                            }
                            setStyle("-fx-font-family: monospace; -fx-border-width: 0.25px; -fx-border-color: lightgrey;");
                            setTextOverrun(OverrunStyle.ELLIPSIS);
                            setText(item.toString());
                        }
                    }
                };
            }

        });
        FXUtils.addAutoScroll(javaScriptListView);
        VBox.setVgrow(javaScriptListView, Priority.ALWAYS);
    }

    public void clear() {
        if (!javaScriptListView.getItems().isEmpty())
            javaScriptListView.getItems().clear();
    }

    public void handleError(WebErrorEvent event) {
        printError(event.getMessage());
    }

    public void handleAlert(WebEvent<String> event) {
        printAlert(event.getData());
    }

    public void printError(String message) {
        javaScriptListView.getItems().add("error('" + message.replace("'", "\\'") + "')");
    }

    public void printAlert(String message) {
        javaScriptListView.getItems().add("alert('" + message.replace("'", "\\'") + "')");
    }

    public class JSCommand {
        private final String command;

        public JSCommand(String text) {
            command = text;
        }

        public String getCommand() {
            return command;
        }

        public String toString() {
            return ">>> " + command;
        }
    }

    public class JSError {
        private final String message;

        public JSError(String text) {
            message = text;
        }

        public String toString() {
            return message;
        }
    }
}
