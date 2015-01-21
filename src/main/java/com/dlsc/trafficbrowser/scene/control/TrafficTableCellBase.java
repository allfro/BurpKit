package com.dlsc.trafficbrowser.scene.control;

import com.dlsc.trafficbrowser.beans.Traffic;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.image.ImageView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;

public abstract class TrafficTableCellBase extends TableCell<Traffic, Traffic> {

	private ImageView imageView;
	private Label label1;
	private Label label2;
	private BorderPane borderPane;
	private VBox box;

	public TrafficTableCellBase() {
		imageView = new ImageView();
		label1 = new Label();
		label2 = new Label();
		label2.getStyleClass().add("label2");

		borderPane = new BorderPane();
		borderPane.setLeft(imageView);
		BorderPane.setMargin(imageView, new Insets(0, 10, 0, 5));
		BorderPane.setAlignment(imageView, Pos.CENTER);

		box = new VBox();
		box.setAlignment(Pos.CENTER_LEFT);
		box.getChildren().add(label1);
		box.getChildren().add(label2);
		borderPane.setCenter(box);
		BorderPane.setAlignment(box, Pos.CENTER);

		setGraphic(borderPane);
		setContentDisplay(ContentDisplay.GRAPHIC_ONLY);
	}

	public ImageView getImageView() {
		return imageView;
	}

	@Override
	protected void updateItem(Traffic traffic, boolean empty) {
		super.updateItem(traffic, empty);

		if (!empty && traffic != null) {
			label1.setText(lookupText1(traffic));
			label2.setText(lookupText2(traffic));
			borderPane.setVisible(true);

			if (traffic.isError()) {
				if (!label1.getStyleClass().contains("error")) {
					label1.getStyleClass().add("error");
					label2.getStyleClass().add("error");
				}
			} else {
				label1.getStyleClass().remove("error");
				label2.getStyleClass().remove("error");
			}

			if (label2.getText() == null) {
				box.getChildren().remove(label2);
			} else if (!box.getChildren().contains(label2)) {
				box.getChildren().add(label2);
			}

			String imageStyle = lookupImageStyle(traffic);
			if (imageStyle == null) {
				imageView.getStyleClass().clear();
				borderPane.setLeft(null);
			} else {
				imageView.getStyleClass().setAll(imageStyle);
				borderPane.setLeft(imageView);
			}
		} else {
			borderPane.setVisible(false);
		}
	}

	protected String lookupImageStyle(Traffic traffic) {
		return null;
	}

	protected String lookupText1(Traffic traffic) {
		return null;
	}

	protected String lookupText2(Traffic traffic) {
		return null;
	}
}
