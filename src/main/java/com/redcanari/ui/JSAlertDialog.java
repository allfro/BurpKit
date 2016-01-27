package com.redcanari.ui;

import com.sun.javafx.tk.Toolkit;
import javafx.collections.ObservableList;
import javafx.geometry.Bounds;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.*;
import javafx.stage.Modality;
import javafx.stage.StageStyle;

/**
 * Created by ndouba on 15-07-02.
 */
public class JSAlertDialog extends Alert {

    private final StackPane stackPane;
    private final Node owner;

    public JSAlertDialog(Node owner) {
        super(AlertType.INFORMATION);
        this.owner = owner;
        Parent parent = owner.getParent();
        if (!(parent instanceof StackPane)) {
            if (parent instanceof Pane) {
                ObservableList<Node> nodes = ((Pane) parent).getChildren();
                Bounds bounds = owner.getBoundsInParent();
                nodes.remove(owner);
                stackPane = new StackPane();
                AnchorPane.setBottomAnchor(stackPane, AnchorPane.getBottomAnchor(owner));
                AnchorPane.setTopAnchor(stackPane, AnchorPane.getTopAnchor(owner));
                AnchorPane.setLeftAnchor(stackPane, AnchorPane.getLeftAnchor(owner));
                AnchorPane.setRightAnchor(stackPane, AnchorPane.getRightAnchor(owner));
                HBox.setHgrow(stackPane, HBox.getHgrow(owner));
                VBox.setVgrow(stackPane, VBox.getVgrow(owner));
                stackPane.getChildren().add(owner);
                nodes.add(stackPane);
            } else {
                throw new RuntimeException("Parent of owner needs to be a subclass of Pane.");
            }
        } else {
            stackPane = (StackPane)parent;
        }
//        initOwner(owner.getScene().getWindow());
        initModality(Modality.NONE);
        initStyle(StageStyle.UNDECORATED);
        setHeaderText("JavaScript Alert");
    }

    public void alert(String message) {
        setContentText(message);
        Pane dialogPane = getDialogPane();
        dialogPane.setMaxSize(Region.USE_PREF_SIZE, Region.USE_PREF_SIZE);
        dialogPane.setEffect(new DropShadow());
        HBox rootPane = new HBox(dialogPane);
        rootPane.setAlignment(Pos.CENTER);
        rootPane.setStyle("-fx-background-color: rgba(0,0,0,0.5);");
        stackPane.getChildren().add(rootPane);
        ButtonBar bar = (ButtonBar)dialogPane.getChildren().get(2);
        Button button = (Button)bar.getButtons().get(0);
        button.setOnMouseClicked((event) -> {
            Toolkit.getToolkit().exitNestedEventLoop(this, null);
            stackPane.getChildren().remove(rootPane);
        });
        Toolkit.getToolkit().enterNestedEventLoop(this);
    }
}
