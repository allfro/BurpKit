package com.redcanari.ui;

import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.scene.control.ListView;
import javafx.scene.control.TableView;

/**
 * Created by ndouba on 14-12-27.
 */
public class FXUtils {
    public static <S> void addAutoScroll(final TableView<S> view) {
        if (view == null) {
            throw new NullPointerException();
        }

        view.getItems().addListener((ListChangeListener<S>) (c -> {
            c.next();
            final int size = view.getItems().size();
            if (size > 0) {
                view.scrollTo(size - 1);
            }
        }));
    }

    public static <S> void addAutoScroll(final ListView<S> view) {
        if (view == null) {
            throw new NullPointerException();
        }

        view.getItems().addListener((ListChangeListener<S>) (c -> {
            c.next();
            if (c.wasAdded())
                view.scrollTo(c.getTo());
        }));
    }
}
