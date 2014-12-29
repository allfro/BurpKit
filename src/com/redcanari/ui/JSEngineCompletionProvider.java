package com.redcanari.ui;

import com.sun.glass.ui.Application;
import javafx.scene.web.WebEngine;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;
import org.fife.ui.autocomplete.Completion;
import org.fife.ui.autocomplete.DefaultCompletionProvider;
import org.fife.ui.autocomplete.ShorthandCompletion;
import org.fife.ui.autocomplete.Util;

import javax.swing.text.JTextComponent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * Created by ndouba on 14-12-16.
 */
public class JSEngineCompletionProvider extends DefaultCompletionProvider {

    private WebEngine webEngine;
    private List<Completion> lastJSCompletions;

    public JSEngineCompletionProvider(WebEngine webEngine) {
        super();
        this.webEngine = webEngine;
        setAutoActivationRules(true, ".");
    }

    private String getObjectParent(String text) {
        if (text.contains("."))
            return text.replaceFirst("\\.[^\\.]*$", "");
        return "this";
    }

    private String getObjectChild(String text) {
        if (text.contains("."))
            return text.replaceFirst("^.+\\.([^\\.]*)$", "$1");
        return "";
    }

    @Override
    protected boolean isValidChar(char ch) {
        return Character.isLetterOrDigit(ch) || ch == 95 || ch == 46;
    }

    private List<Completion> enumerateJSObject(String text) {

        final String objectParent = getObjectParent(text);
        final String objectChild = getObjectChild(text);

        FutureTask<List<Completion>> futureTask = new FutureTask<>(() -> {
            try {
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
                List<Completion> jsCompletions = new ArrayList<>();
                for (int i = 0; i < length; i++) {
                    String member = (String) object.getSlot(i);
                    jsCompletions.add(new ShorthandCompletion(
                            this,
                            member,
                            (objectParent.isEmpty())?member:objectParent + "." + member
                    ));
                }
                return jsCompletions;
            } catch (JSException e) {
                e.printStackTrace();
                return null;
            }
        });

        Application.invokeLater(futureTask);

        try {
            List<Completion> completions = futureTask.get();
            if (completions != null)
                lastJSCompletions = completions;
            return lastJSCompletions;
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }



    protected List<Completion> getCompletionsImpl(JTextComponent comp) {
        ArrayList<Completion> tempCompletions = new ArrayList<>();
        tempCompletions.addAll(this.completions);

        ArrayList retVal = new ArrayList();
        String text = this.getAlreadyEnteredText(comp);

        List<Completion> jsCompletions = enumerateJSObject(text);
        if (jsCompletions != null)
            tempCompletions.addAll(jsCompletions);

        Collections.sort(tempCompletions, this.comparator);

        if(text != null) {
            text = getObjectChild(text);
            int index = Collections.binarySearch(tempCompletions, text, this.comparator);
            if(index < 0) {
                index = -index - 1;
            } else {
                for(int c = index - 1; c > 0 && this.comparator.compare(tempCompletions.get(c), text) == 0; --c) {
                    retVal.add(tempCompletions.get(c));
                }
            }

            while(index < tempCompletions.size()) {
                Completion completion = (Completion)tempCompletions.get(index);
                if(!Util.startsWithIgnoreCase(completion.getInputText(), text)) {
                    break;
                }

                retVal.add(completion);
                ++index;
            }
        }

        return retVal;
    }

}
