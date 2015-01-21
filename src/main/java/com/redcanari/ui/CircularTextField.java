package com.redcanari.ui;

import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.util.Callback;
import org.controlsfx.control.textfield.AutoCompletionBinding;
import org.controlsfx.control.textfield.TextFields;

import java.util.*;

/**
 * Created by ndouba on 14-12-27.
 */
public class CircularTextField extends BaseTextField {

    int currentIndex = -1;
    private List<String> history = new ArrayList<>();



    public CircularTextField() {
        super();
        setOnKeyPressed(this::handleKeyPressed);
    }


    public void handleKeyPressed(KeyEvent event) {
        switch (event.getCode()) {
            case ENTER:
                currentIndex = -1;
                history.add(0, getText().trim());
                break;
            case UP:
                if (history.size() == 0)
                    break;
                else if (currentIndex != history.size() - 1)
                    currentIndex++;
                setText(history.get(currentIndex));
                Platform.runLater(this::end);
                break;
            case DOWN:
                if (currentIndex != -1)
                    currentIndex--;
                setText((currentIndex == -1)?"":history.get(currentIndex));
            default:
                break;
        }
    }

}
