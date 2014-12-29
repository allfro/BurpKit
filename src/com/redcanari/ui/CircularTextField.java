package com.redcanari.ui;

import javafx.scene.control.TextField;
import javafx.scene.input.KeyEvent;
import org.controlsfx.control.textfield.AutoCompletionBinding;
import org.controlsfx.control.textfield.TextFields;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by ndouba on 14-12-27.
 */
public class CircularTextField extends TextField {

    int currentIndex = -1;
//    private Set<String> possibleSuggestions = new HashSet<>();
    private List<String> history = new ArrayList<>();
//    private AutoCompletionBinding<String> autoCompletionBinding;

    public CircularTextField() {
        setOnKeyPressed(this::handleKeyPressed);
    }

    public void handleKeyPressed(KeyEvent event) {
        switch (event.getCode()) {
            case ENTER:
                currentIndex = 0;
                history.add(0, getText().trim());
//                autoCompletionLearnWord(getText().trim());
                break;
            case UP:
                if (history.size() == 0)
                    break;
                else if (currentIndex != history.size() - 1)
                    currentIndex++;
                setText(history.get(currentIndex));
                break;
            case DOWN:
                if (currentIndex != -1)
                    currentIndex--;
                setText((currentIndex == -1)?"":history.get(currentIndex));
            default:
                break;
        }
    }

//    private void autoCompletionLearnWord(String newWord) {
//        possibleSuggestions.add(newWord);
//
//        // we dispose the old binding and recreate a new binding
//        if (autoCompletionBinding != null) {
//            autoCompletionBinding.dispose();
//        }
//
//        autoCompletionBinding = TextFields.bindAutoCompletion(this, possibleSuggestions);
//    }

}
