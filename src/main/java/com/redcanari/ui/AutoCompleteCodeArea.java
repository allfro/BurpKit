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

/**
 * Created by ndouba on 15-05-20.
 */

import com.redcanari.ui.providers.AutoCompletionProvider;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.event.EventHandler;
import javafx.scene.control.ListView;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.stage.Popup;
import org.fxmisc.richtext.*;
import org.reactfx.EventStream;
import org.reactfx.util.Try;

import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutoCompleteCodeArea extends CodeArea implements EventHandler<KeyEvent> {

    private static final String[] KEYWORDS = new String[] {
            "do", 
            "if",
            "in",
            "for",
            "let",
            "new",
            "try",
            "var",
            "case",
            "else",
            "enum",
            "eval",
            "null",
            "this",
            "true",
            "void",
            "with",
            "await",
            "break",
            "catch",
            "class",
            "const",
            "false",
            "super",
            "throw",
            "while",
            "yield",
            "delete",
            "export",
            "import",
            "public",
            "return",
            "static",
            "switch",
            "typeof",
            "default",
            "extends",
            "finally",
            "package",
            "private",
            "continue",
            "debugger",
            "function",
            "arguments",
            "interface",
            "protected",
            "implements",
            "instanceof"
    };

    private static final String KEYWORD_PATTERN = "\\b(" + String.join("|", KEYWORDS) + ")\\b";
    private static final String PAREN_PATTERN = "\\(|\\)";
    private static final String BRACE_PATTERN = "\\{|\\}";
    private static final String BRACKET_PATTERN = "\\[|\\]";
    private static final String SEMICOLON_PATTERN = "\\;";
    private static final String STRING_PATTERN = "[\"']([^\"'\\\\]|\\\\.)*[\"']";
    private static final String COMMENT_PATTERN = "//[^\n]*" + "|" + "/\\*(.|\\R)*?\\*/";

    private static final Pattern PATTERN = Pattern.compile(
            "(?<KEYWORD>" + KEYWORD_PATTERN + ")"
                    + "|(?<PAREN>" + PAREN_PATTERN + ")"
                    + "|(?<BRACE>" + BRACE_PATTERN + ")"
                    + "|(?<BRACKET>" + BRACKET_PATTERN + ")"
                    + "|(?<SEMICOLON>" + SEMICOLON_PATTERN + ")"
                    + "|(?<STRING>" + STRING_PATTERN + ")"
                    + "|(?<COMMENT>" + COMMENT_PATTERN + ")"
    );

    private final ExecutorService executor;
    private final Popup popup = new Popup();
    private final AutoCompletionProvider autoCompletionProvider;
    private ObservableList<String> completions;
    private final ListView<String> listView = new ListView<>();
    private boolean tracking = false;
    private int suggestionStart = 0;

    public AutoCompleteCodeArea(AutoCompletionProvider provider) {
        super();

        this.autoCompletionProvider = provider;

        executor = Executors.newSingleThreadExecutor();

        setParagraphGraphicFactory(LineNumberFactory.get(this));

        EventStream<PlainTextChange> textChanges = plainTextChanges();
        textChanges
                .successionEnds(Duration.ofMillis(500))
                .supplyTask(this::computeHighlightingAsync)
                .awaitLatest(textChanges)
                .map(Try::get)
                .subscribe(this::applyHighlighting);
        getStylesheets().add(AutoCompleteCodeArea.class.getResource("/stylesheets/java-keywords.css").toExternalForm());

        popup.setAutoFix(true);
        popup.setAutoHide(true);
        popup.setHideOnEscape(true);
        popup.getContent().add(listView);
        setPopupWindow(popup);

        listView.setMaxHeight(100);

        listView.setOnMouseClicked(event -> {
            autoCompletionProvider.applySuggestion(this, listView.getSelectionModel().getSelectedItem());
            reset();
        });

        caretPositionProperty().addListener((observable, oldValue, newValue) -> {
            String text = getText();
            int oldValueInt = oldValue;
            int newValueInt = newValue;

            if (oldValueInt < newValueInt && autoCompletionProvider.shouldShowPopup(text.charAt(oldValueInt)))
                suggestionStart = newValueInt;
        });

        setOnKeyReleased(this);
    }

    private void correctSuggestedStart() {
        String text = getText();
        int start = getCaretPosition() - 1;

        for (; start >= 0; start--) {
            char c = text.charAt(start);
            if ("~!@#%^&*()+`-={}|[]\\;':\"<>?,/ \t\n\r".indexOf(c) == -1)
                continue;
            break;
        }
        suggestionStart = start + 1;
    }

    @Override
    public void handle(KeyEvent event) {
        KeyCode keyCode = event.getCode();
        int caret = getCaretPosition();

        if (event.isControlDown()) {
            reset();
            switch(keyCode) {
                case C:
                    copy();
                    break;
                case X:
                    cut();
                    break;
                case V:
                    paste();
                    break;
                case Z:
                    undo();
                    break;
                case Y:
                    redo();
                    break;
                case A:
                    selectAll();
            }
            return;
        }

        if (popup.isShowing()) {
            popup.show(getScene().getWindow());
        }
        if (autoCompletionProvider.shouldShowPopup(keyCode) || (event.isAltDown() && keyCode == KeyCode.SPACE)) {
            if (event.isAltDown() && keyCode == KeyCode.SPACE)
                correctSuggestedStart();
            completions = FXCollections.observableArrayList();
            completions.addAll(autoCompletionProvider.getCompletions(this));
            FXCollections.sort(completions);
            tracking = true;
            if (completions.size() > 0) {
                if (!popup.isShowing())
                    popup.show(getScene().getWindow());
                listView.setItems(completions);
                listView.getSelectionModel().selectFirst();
                listView.requestFocus();
            }
        } else if ((keyCode == KeyCode.ENTER || keyCode == KeyCode.TAB) && popup.isShowing()) {
            String item = listView.getSelectionModel().getSelectedItem();
            if (item == null)
                item = listView.getItems().get(0);
            autoCompletionProvider.applySuggestion(this, item);
            reset();
        } else if ((event.getText().matches("[ -~]") || keyCode == KeyCode.BACK_SPACE) && (popup.isShowing() || tracking)) {
            if (!tracking) {
                tracking = true;
            } else if (caret < suggestionStart) {
                reset();
                return;
            }
            FilteredList<String> filteredList = completions.filtered(s -> s.startsWith(getText(suggestionStart, caret)));
            if (filteredList.size() == 0) {
                popup.hide();
                return;
            }
            else if (!popup.isShowing() && filteredList.size() > 0)
                popup.show(getScene().getWindow());
            listView.setItems(filteredList);
            listView.getSelectionModel().selectFirst();
            listView.requestFocus();
        } else if ((keyCode != KeyCode.UP && keyCode != KeyCode.DOWN && keyCode != KeyCode.PAGE_DOWN &&
                keyCode != KeyCode.PAGE_UP && !keyCode.isModifierKey()) && popup.isShowing()) {
            reset();
        }
    }

    public int getSuggestionStart() {
        return suggestionStart;
    }

    private void reset() {
        popup.hide();
        tracking = false;
    }

    private Task<StyleSpans<Collection<String>>> computeHighlightingAsync() {
        String text = getText();
        Task<StyleSpans<Collection<String>>> task = new Task<StyleSpans<Collection<String>>>() {
            @Override
            protected StyleSpans<Collection<String>> call() throws Exception {
                return computeHighlighting(text);
            }
        };
        executor.execute(task);
        return task;
    }

    private void applyHighlighting(StyleSpans<Collection<String>> highlighting) {
        setStyleSpans(0, highlighting);
    }

    private static StyleSpans<Collection<String>> computeHighlighting(String text) {
        Matcher matcher = PATTERN.matcher(text);
        int lastKwEnd = 0;
        StyleSpansBuilder<Collection<String>> spansBuilder
                = new StyleSpansBuilder<>();
        while(matcher.find()) {
            String styleClass =
                    matcher.group("KEYWORD") != null ? "keyword" :
                            matcher.group("PAREN") != null ? "paren" :
                                    matcher.group("BRACE") != null ? "brace" :
                                            matcher.group("BRACKET") != null ? "bracket" :
                                                    matcher.group("SEMICOLON") != null ? "semicolon" :
                                                            matcher.group("STRING") != null ? "string" :
                                                                    matcher.group("COMMENT") != null ? "comment" :
                                                                            null; /* never happens */ assert styleClass != null;
            spansBuilder.add(Collections.emptyList(), matcher.start() - lastKwEnd);
            spansBuilder.add(Collections.singleton(styleClass), matcher.end() - matcher.start());
            lastKwEnd = matcher.end();
        }
        spansBuilder.add(Collections.emptyList(), text.length() - lastKwEnd);
        return spansBuilder.create();
    }

}
