package com.dlsc.trafficbrowser.scene.control;

import java.time.Instant;

import com.dlsc.trafficbrowser.beans.Traffic;
import javafx.beans.InvalidationListener;
import javafx.scene.control.SkinBase;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

public class TrafficBrowserSkin extends SkinBase<TrafficBrowser> {

	private TableColumn<Traffic, Traffic> timelineColumn;

	public TrafficBrowserSkin(TrafficBrowser browser) {
		super(browser);

		TableView<Traffic> table = new TableView<>();
		table.setItems(browser.getTraffic());
		table.setFixedCellSize(40);

		// name column
		TableColumn<Traffic, Traffic> nameColumn = new TableColumn<>("Name");
		nameColumn.setPrefWidth(250);
		nameColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		nameColumn.setCellFactory(column -> new TrafficNamePathTableCell());
		table.getColumns().add(nameColumn);

		// method column
		TableColumn<Traffic, Traffic> methodColumn = new TableColumn<>("Method");
		methodColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		methodColumn.setCellFactory(column -> new TrafficMethodTableCell());

		table.getColumns().add(methodColumn);

		// status column
		TableColumn<Traffic, Traffic> statusColumn = new TableColumn<>("Status");
		statusColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		statusColumn.setCellFactory(column -> new TrafficStatusTableCell());
		table.getColumns().add(statusColumn);

		// type column
		TableColumn<Traffic, Traffic> typeColumn = new TableColumn<>("Type");
		typeColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		typeColumn.setCellFactory(column -> new TrafficTypeTableCell());
		table.getColumns().add(typeColumn);

		// initiator column
		TableColumn<Traffic, Traffic> initiatorColumn = new TableColumn<>(
				"Initiator");
		initiatorColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		initiatorColumn
				.setCellFactory(column -> new TrafficInitiatorTableCell());
		table.getColumns().add(initiatorColumn);

		// size column
		TableColumn<Traffic, Traffic> sizeColumn = new TableColumn<>("Size");
		sizeColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		sizeColumn.setCellFactory(column -> new TrafficSizeTableCell());
		table.getColumns().add(sizeColumn);

		// time column
		TableColumn<Traffic, Traffic> timeColumn = new TableColumn<>("Time");
		timeColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		timeColumn.setCellFactory(column -> new TrafficTimeTableCell());
		table.getColumns().add(timeColumn);

		// graphics column
		timelineColumn = new TableColumn<>("Timeline");
		timelineColumn
				.setCellValueFactory(new PropertyValueFactory<Traffic, Traffic>(
						"me"));
		timelineColumn.setPrefWidth(600);
		timelineColumn.setCellFactory(column -> new TrafficTimelineTableCell(
				getSkinnable()));

		InvalidationListener listener = observable -> updateTimelineColumnHeader();

		updateTimelineColumnHeader();

//		browser.startTimeProperty().addListener(listener);
//		browser.endTimeProperty().addListener(listener);

		table.getColumns().add(timelineColumn);

		getChildren().add(table);
	}

	private void updateTimelineColumnHeader() {
		Instant st = getSkinnable().getStartTime();
		Instant et = getSkinnable().getEndTime();

		long millis = et.toEpochMilli() - st.toEpochMilli();

		timelineColumn.setText("Timeline (Duration: " + millis + " ms)");
	}
}
