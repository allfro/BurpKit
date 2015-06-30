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

package com.dlsc.trafficbrowser.scene.control;

import com.dlsc.trafficbrowser.beans.Traffic;
import javafx.beans.InvalidationListener;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.transformation.SortedList;
import javafx.event.EventHandler;
import javafx.scene.control.SkinBase;
import javafx.scene.control.SortEvent;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.time.Duration;
import java.util.Comparator;


/**
 * @author Dirk Lemmermann
 * @since 2015-01-24
 * @version 1.0
 */
public class TrafficBrowserSkin extends SkinBase<TrafficBrowser> {

	private TableColumn<Traffic, Traffic> timelineColumn;

	public TrafficBrowserSkin(TrafficBrowser browser) {
		super(browser);

		TableView<Traffic> table = new TableView<>();

        final Comparator<Traffic> TIMELINE_COMPARATOR = (t1, t2) -> t1.getStartTime().compareTo(t2.getStartTime());
        final ObjectProperty<Comparator<? super Traffic>> TIMELINE_COMPARATOR_WRAPPER = new SimpleObjectProperty<>(TIMELINE_COMPARATOR);


        SortedList<Traffic> sortedData = new SortedList<>(browser.getTraffic());
        sortedData.comparatorProperty().bind(TIMELINE_COMPARATOR_WRAPPER);

		table.setItems(sortedData);
		table.setFixedCellSize(40);

        table.setOnSort(new EventHandler<SortEvent<TableView<Traffic>>>() {
            @Override
            public void handle(SortEvent<TableView<Traffic>> event) {
                sortedData.comparatorProperty().unbind();
                if (table.getSortOrder().size() == 0) {
                    sortedData.comparatorProperty().bind(TIMELINE_COMPARATOR_WRAPPER);
                    table.setSortPolicy(param -> true);
                } else {
                    sortedData.comparatorProperty().bind(table.comparatorProperty());
                }
            }
        });

		// name column
		TableColumn<Traffic, Traffic> nameColumn = new TableColumn<>("Name");
		nameColumn.setPrefWidth(250);
		nameColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		nameColumn.setCellFactory(column -> new TrafficNamePathTableCell());
		table.getColumns().add(nameColumn);

		// method column
		TableColumn<Traffic, Traffic> methodColumn = new TableColumn<>("Method");
		methodColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		methodColumn.setCellFactory(column -> new TrafficMethodTableCell());

		table.getColumns().add(methodColumn);

		// status column
		TableColumn<Traffic, Traffic> statusColumn = new TableColumn<>("Status");
		statusColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		statusColumn.setCellFactory(column -> new TrafficStatusTableCell());
		table.getColumns().add(statusColumn);

		// type column
		TableColumn<Traffic, Traffic> typeColumn = new TableColumn<>("Type");
		typeColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		typeColumn.setCellFactory(column -> new TrafficTypeTableCell());
		table.getColumns().add(typeColumn);

		// initiator column
		TableColumn<Traffic, Traffic> initiatorColumn = new TableColumn<>(
				"Initiator");
		initiatorColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		initiatorColumn
				.setCellFactory(column -> new TrafficInitiatorTableCell());
		table.getColumns().add(initiatorColumn);

		// size column
		TableColumn<Traffic, Traffic> sizeColumn = new TableColumn<>("Size");
		sizeColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		sizeColumn.setCellFactory(column -> new TrafficSizeTableCell());
		table.getColumns().add(sizeColumn);

		// time column
		TableColumn<Traffic, Traffic> timeColumn = new TableColumn<>("Time");
		timeColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		timeColumn.setCellFactory(column -> new TrafficTimeTableCell());
        timeColumn.setComparator((o1, o2) -> o1.getDuration().compareTo(o2.getDuration()));
		table.getColumns().add(timeColumn);

		// graphics column
		timelineColumn = new TableColumn<>("Timeline");
		timelineColumn
				.setCellValueFactory(new PropertyValueFactory<>(
                        "me"));
		timelineColumn.setPrefWidth(600);
		timelineColumn.setCellFactory(column -> new TrafficTimelineTableCell(
				getSkinnable()));
        timelineColumn.setComparator((o1, o2) -> o1.getDuration().compareTo(o2.getDuration()));

        table.getItems().addListener((InvalidationListener) observable -> updateTimelineColumnHeader());

		updateTimelineColumnHeader();

		table.getColumns().add(timelineColumn);

		getChildren().add(table);
	}

	private void updateTimelineColumnHeader() {
		String timeSpan;
		Duration d = Duration.between(getSkinnable().getStartTime(), getSkinnable().getEndTime());

		long seconds = d.getSeconds();
		long hours = (int) Math.floor(seconds/3600);
		seconds %= 3600;
		long minutes = (int) Math.floor(seconds/60);
		seconds %= 60;

		if (hours > 0) {
			timeSpan = String.format("%d.%02dh", hours, (int) Math.floor(minutes/60.0*100));
		} else if (minutes > 0) {
			timeSpan = String.format("%d.%02dh", minutes, (int)Math.floor(seconds/60.0*100));
		} else {
			int nanos = d.getNano();
			int millis = (int)Math.floor(d.getNano() / 1000000);
			nanos %= 1000000;
			if (seconds > 0) {
				timeSpan = String.format("%d.%03ds", seconds, millis);
			} else {
				timeSpan = String.format("%d.%03dms", millis, (int) Math.floor(nanos / 1000));
			}
		}

		timelineColumn.setText("Timeline (Duration: " + timeSpan + ")");
	}
}
