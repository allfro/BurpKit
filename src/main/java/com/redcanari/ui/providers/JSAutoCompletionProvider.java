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

package com.redcanari.ui.providers;

import com.redcanari.js.Helpers;
import com.redcanari.ui.AutoCompleteCodeArea;
import com.redcanari.ui.AutoCompleteTextField;
import com.redcanari.util.ResourceUtils;
import javafx.scene.input.KeyCode;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSObject;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;

/**
 * Created by ndouba on 15-06-18.
 */
public class JSAutoCompletionProvider implements AutoCompletionProvider {

    private final WebEngine webEngine;

    private final String introspectionScript = ResourceUtils.getResourceContentsAsString("/scripts/enumerateObject.js");


    public JSAutoCompletionProvider(WebEngine webEngine) {
        this.webEngine = webEngine;
    }

    /**
     * Returns the last JavaScript token from where the cursor is in textField.
     *
     * @return the last JavaScript token.
     */
    private String getLastToken(AutoCompleteTextField textField) {
        String text = textField.getText();
        int end = textField.getCaretPosition() - 1;
        int start;

        for (start = end; start >= 0; start--) {
            char c = text.charAt(start);
            if ("~!@#%^&*()+`-={}|[]\\;':\"<>?,/ \t".indexOf(c) == -1)
                continue;
            break;
        }
        return text.substring(start + 1, end);
    }

    /**
     * Returns the last JavaScript token from where the cursor is in the codeArea.
     *
     * @return the last JavaScript token.
     */
    private String getLastToken(AutoCompleteCodeArea codeArea) {
        String text = codeArea.getText();
        int end = codeArea.getCaretPosition() - 1;
        int start;

        for (start = end; start >= 0; start--) {
            char c = text.charAt(start);
            if ("~!@#%^&*()+`-={}|[]\\;':\"<>?,/ \t".indexOf(c) == -1)
                continue;
            break;
        }
        return text.substring(start + 1, end);
    }

    private List<String> enumerateJSObject(String text) {
        if (text.isEmpty())
            return null;

        Object o = webEngine.executeScript(text);

        if (o instanceof JSObject || o instanceof String) {
            JSObject object = (JSObject) webEngine.executeScript(String.format(introspectionScript, (o instanceof String)?"String":text));
            return Helpers.toJavaList(object);
        }

        List<String> completions = new ArrayList<>();
        for (Method m : o.getClass().getDeclaredMethods()) {
            String name = m.getName();
            if (Modifier.isPublic(m.getModifiers()) && !completions.contains(name))
                completions.add(name);
        }
        for (Field f : o.getClass().getDeclaredFields()) {
            if (Modifier.isPublic(f.getModifiers()))
                completions.add(f.getName());
        }

        return completions;
    }

    public boolean isInteger(String s) {
        return isInteger(s,10);
    }

    public boolean isInteger(String s, int radix) {
        if(s.isEmpty()) return false;
        for(int i = 0; i < s.length(); i++) {
            if (i == 0 && s.charAt(i) == '-') {
                if(s.length() == 1) return false;
                else continue;
            }
            if (Character.digit(s.charAt(i), radix) < 0) return false;
        }
        return true;
    }


    @Override
    public Collection<String> getCompletions(Object source) {
        if (source instanceof AutoCompleteTextField)
            return enumerateJSObject(getLastToken((AutoCompleteTextField)source));
        return enumerateJSObject(getLastToken((AutoCompleteCodeArea)source));
    }

    @Override
    public void applySuggestion(Object target, String text) {
        if (target instanceof AutoCompleteTextField)
            applySuggestion((AutoCompleteTextField)target, text);
        else
            applySuggestion((AutoCompleteCodeArea)target, text);
    }

    public void applySuggestion(AutoCompleteCodeArea codeArea, String text) {
        if (isInteger(text))
            codeArea.replaceText(codeArea.getSuggestionStart() - 1, codeArea.getCaretPosition(), "[" + text + "]");
        else if (!text.matches("^[A-Za-z_$][A-Za-z0-9_$]*$"))
            codeArea.replaceText(codeArea.getSuggestionStart() - 1, codeArea.getCaretPosition(), "['" + text.replace("'", "\\'") + "']");
        else
            codeArea.replaceText(codeArea.getSuggestionStart(), codeArea.getCaretPosition(), text);
    }

    public void applySuggestion(AutoCompleteTextField textField, String text) {
        if (isInteger(text))
            textField.replaceText(textField.getSuggestionStart() - 1, textField.getCaretPosition(), "[" + text + "]");
        else if (!text.matches("^[A-Za-z_$][A-Za-z0-9_$]*$"))
            textField.replaceText(textField.getSuggestionStart() - 1, textField.getCaretPosition(), "['" + text.replace("'", "\\'") + "']");
        else
            textField.replaceText(textField.getSuggestionStart(), textField.getCaretPosition(), text);
    }

    @Override
    public boolean shouldShowPopup(KeyCode c) {
        return c == KeyCode.PERIOD;
    }

    @Override
    public boolean shouldShowPopup(char c) {
        return c == '.';
    }
}
