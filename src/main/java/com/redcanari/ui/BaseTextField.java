package com.redcanari.ui;

import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;

/**
 * Created by ndouba on 15-01-01.
 */
public class BaseTextField extends TextField {

    private boolean focusWasRequested = false;

    public BaseTextField() {
        setOnMouseClicked(this::handleMouseClick);
    }

    private void handleMouseClick(MouseEvent mouseEvent) {
        if (!focusWasRequested)
            return;
        focusWasRequested = false;
        if (!getText().isEmpty())
            selectAll();
    }

    @Override
    public void requestFocus() {
        super.requestFocus();
        focusWasRequested = true;
    }

}
