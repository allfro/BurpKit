package com.redcanari.ui;

import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker;
import javafx.event.ActionEvent;
import javafx.scene.web.WebEngine;

/**
 * Created by ndouba on 15-01-01.
 */
public class URLTextField extends BaseTextField {

    private final WebEngine webEngine;

    public URLTextField(WebEngine webEngine) {
        this.webEngine = webEngine;
        webEngine.getLoadWorker().stateProperty().addListener(this::workerStateChanged);
        setOnAction(this::handleOnAction);
    }

    private void handleOnAction(ActionEvent actionEvent) {
        String url = getText();
        if (!url.matches("^(https?|ftp|about|javascript|data|file|telnet):(//)?.*"))
            url = "http://" + url;
        webEngine.load(url);
    }

    public void workerStateChanged(ObservableValue<? extends Worker.State> observable, Worker.State oldValue, Worker.State newValue) {
        if (newValue == Worker.State.SCHEDULED) {
            textProperty().bind(webEngine.locationProperty());
        } else if (newValue != Worker.State.RUNNING) {
            textProperty().unbind();
        }
    }

    @Override
    public void requestFocus() {
        textProperty().unbind();
        super.requestFocus();
    }

}
