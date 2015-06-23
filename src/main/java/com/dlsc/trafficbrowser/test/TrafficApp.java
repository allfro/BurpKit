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

package com.dlsc.trafficbrowser.test;

import com.dlsc.trafficbrowser.beans.Traffic;
import com.dlsc.trafficbrowser.scene.control.TrafficBrowser;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.scene.Scene;
import javafx.scene.control.ContextMenu;
import javafx.scene.control.MenuItem;
import javafx.stage.Stage;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class TrafficApp extends Application {

	@Override
	public void start(Stage stage) throws Exception {
		final TrafficBrowser browser = new TrafficBrowser();
		Scene scene = new Scene(browser);
		stage.setScene(scene);
		stage.setWidth(1400);
		stage.setHeight(800);
		stage.show();

		Instant now = Instant.now();
		browser.setStartTime(now);
		browser.setEndTime(now);

		final Simulation simulation = new Simulation();
		simulation.setOnSucceeded(evt -> {
			List<Traffic> traffic = simulation.getValue();
			browser.getTraffic().addAll(traffic);
			for (Traffic t : traffic) {
				if (t.getEndTime().isAfter(browser.getEndTime())) {
					browser.setEndTime(t.getEndTime());
				}
			}
		});

		Thread thread = new Thread() {
			@Override
			public void run() {
				for (int i = 0; i < 50; i++) {
					final long sleepDuration = (long) (Math.random() * 2000);

					try {
						Thread.sleep(sleepDuration);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}

					Platform.runLater(() -> {
						simulation.setMaximumDuration(sleepDuration);
						simulation.restart();
					});
				}
			};
		};

		thread.setDaemon(true);

		ContextMenu menu = new ContextMenu();
		MenuItem item = new MenuItem("Run Simulation");
		item.setOnAction(evt -> thread.start());
		menu.getItems().add(item);
		browser.setContextMenu(menu);
	}

	public static void main(String[] args) {
		launch(args);
	}

	public static int count = 0;

	class Simulation extends Service<List<Traffic>> {

		private long maximumDuration;

		@Override
		protected Task<List<Traffic>> createTask() {
			return new SimulationTask(maximumDuration);
		}

		public void setMaximumDuration(long duration) {
			this.maximumDuration = duration;
		}
	}

	public class SimulationTask extends Task<List<Traffic>> {

		private long maximumDuration;

		public SimulationTask(long maximumDuration) {
			this.maximumDuration = maximumDuration;
		}

		@Override
		protected List<Traffic> call() throws Exception {
			int numberOfItems = (int) (Math.random() * 5);

			List<Traffic> list = new ArrayList<Traffic>();
			for (int i = 0; i < numberOfItems; i++) {
				String name = "Item " + count;
				String path = "/item/" + count + "/servlet";
				Instant et = Instant.now();
				Instant st = et.minusMillis((long)(Math.random() * maximumDuration));
				String method = "GET";
				if (Math.random() > .7) {
					method = "POST";
				}
				Integer statusCode = 200;
				String statusText = "OK";
				if (Math.random() > .8) {
					statusCode = 404;
					statusText = "Page not found";
				}
				if (Math.random() > .9) {
					statusCode = 500;
					statusText = "Internal Server Error";
				}

				String type = "text/html";
				switch ((int) (Math.random() * 4)) {
                    case 0:
                        type = "text/css";
                        break;
                    case 1:
                        type = "text/javascript";
                        break;
                    case 2:
                        type = "image/png";
                        break;
				}

				String initiator = "current page";
				String size = Math.max(1, (int) (Math.random() * 200)) + " kb";

				list.add(new Traffic(name, st, et, path, method, statusCode,
						statusText, type, initiator, size));

			}

			return list;
		}
	}
}
