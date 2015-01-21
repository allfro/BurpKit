package com.redcanari.ui;

import javafx.application.Platform;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Worker;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebErrorEvent;
import javafx.scene.web.WebEvent;
import javafx.util.Callback;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;
import org.controlsfx.control.textfield.AutoCompletionBinding;
import org.controlsfx.control.textfield.TextFields;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;


/**
 * Created by ndouba on 14-12-16.
 */
public class JavaScriptConsoleTab extends Tab {

    private final ListView<Object> javaScriptListView = new ListView<>();
    private AutoCompletionBinding<String> autoCompletionBinding;
    private ObservableList<Object> dataSource = FXCollections.observableArrayList();
    private final TextField textField = new CircularTextField();
    private final WebEngine webEngine;

    public JavaScriptConsoleTab(WebEngine webEngine) {
        super("JavaScript Console");

        this.webEngine = webEngine;


        init();
    }

    private class JSCompletionProvider implements Callback<AutoCompletionBinding.ISuggestionRequest, Collection<String>> {

        private String getObjectParent(String text) {
            if (text.contains("."))
                return text.replaceFirst("\\.[^\\.]*$", "");
            return "this";
        }

        private String getObjectChild(String text) {
            if (text.contains("."))
                return text.replaceFirst("^.+\\.([^\\.]*)$", "$1");
            return text;
        }

        private boolean hasMatchingBracesAndBrackets(String text) {
            int open = 0;
//            boolean hasOpenSingleQuote = false;
//            boolean hasOpenDoubleQuote = false;
//            byte previousChar = 0;
            for(byte c : text.getBytes()) {
                switch(c) {
                    case '{':
                    case '[':
                        open++;
                        break;
                    case '}':
                    case ']':
                        open--;
                        break;
//                    case '\'':
//                        if (previousChar == '\\')
//                            continue;
//                        if (!hasOpenSingleQuote)
//                            open++;
//                        else
//                            open--;
//                        hasOpenSingleQuote = !hasOpenSingleQuote;
//                        break;
//                    case '"':
//                        if (previousChar == '\\')
//                            continue;
//                        if (!hasOpenDoubleQuote)
//                            open++;
//                        else
//                            open--;
//                        hasOpenDoubleQuote = !hasOpenDoubleQuote;
//                        break;
                }
//                previousChar = c;
            }
            return open == 0;
        }

        private List<String> enumerateJSObject(String text) {

            if (!hasMatchingBracesAndBrackets(text))
                return null;

            final String objectParent = getObjectParent(text);
            final String objectChild = getObjectChild(text);

            if (objectChild.isEmpty())
                return null;

            FutureTask<List<String>> futureTask = new FutureTask<>(() -> {
                JSObject object = (JSObject) webEngine.executeScript(
                        "(function() { " +
                                "var a = []; " +
                                "for (i in " + objectParent + ") {" +
                                "if (!i.indexOf('" + objectChild + "')) {" +
                                "a[a.length] = i;" +
                                "}" +
                                "} " +
                                "return a;" +
                                "})();"
                );

                int length = (int) object.getMember("length");
                List<String> jsCompletions = new ArrayList<>();

                for (int i = 0; i < length; i++) {
                    String member = (String) object.getSlot(i);
                    jsCompletions.add(objectParent.equals("this")?member:objectParent + "." + member);
                }

                return jsCompletions;
            });

            Platform.runLater(futureTask);

            try {
                return futureTask.get();
            } catch (JSException | InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
            return null;
        }

        @Override
        public Collection<String> call(AutoCompletionBinding.ISuggestionRequest param) {
            if (param.isCancelled() || param.getUserText().isEmpty())
                return null;
            return enumerateJSObject(param.getUserText());
        }
    }


    private void init() {

        this.webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);

        createListView();


        VBox vbox = new VBox();
        vbox.getChildren().addAll(javaScriptListView, createTextField());

        setContent(vbox);

    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.SCHEDULED) {
            clear();
        }
    }

    private Node createTextField() {
        StackPane stackPane = new StackPane();

        textField.setPromptText("execute command...");
        textField.setStyle("-fx-font-family: monospace; -fx-padding: 0.25em 0.416667em  0.333333em 3em");
        textField.disableProperty().bind(webEngine.getLoadWorker().runningProperty());
        autoCompletionBinding = TextFields.bindAutoCompletion(textField, new JSCompletionProvider());


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

    public void printAlert(String message) {
        dataSource.add(new JSAlert(message));
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
            return "alert('" + message.replace("'", "\\'") + "')";
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
