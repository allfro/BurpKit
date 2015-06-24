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

package com.dlsc.trafficbrowser.beans;

import java.time.Duration;
import java.time.Instant;

/**
 * @author Dirk Lemmermann
 * @since 2015-01-24
 * @version 1.0
 */
public class Traffic {

	private final String name;
	private final String path;
	private final String method;
	private Integer statusCode;
	private String statusText;
	private String type;

	public void setStatusCode(Integer statusCode) {
		this.statusCode = statusCode;
	}

	public void setStatusText(String statusText) {
		this.statusText = statusText;
	}

	public void setType(String type) {
		this.type = type;
	}

	public void setSize(String size) {
		this.size = size;
	}

	public void setEndTime(Instant endTime) {
		this.endTime = endTime;
	}

	private final String initiator;
	private String size;

	private final Instant startTime;

	private Instant endTime;

	public Traffic(String name, Instant startTime, String path, String method, String initiator) {
		this.name = name;
		this.startTime = startTime;
		this.path = path;
		this.method = method;
        this.initiator = initiator;
	}

	public Traffic(String name, Instant startTime, Instant endTime,
			String path, String method, Integer statusCode, String statusText,
			String type, String initiator, String size) {

		this.name = name;
		this.startTime = startTime;
		this.endTime = endTime;
		this.path = path;
		this.method = method;
		this.statusCode = statusCode;
		this.statusText = statusText;
		this.type = type;
		this.initiator = initiator;
		this.size = size;
	}

    private String getStyleType() {
        String simpleType = getType().split(";")[0];
        switch (simpleType) {
            case "text/html":
            case "text/xml":
                return "-type-html";
            case "text/javascript":
                return "-type-js";
            case "text/css":
                return "-type-css";
        }

        if (simpleType.contains("javascript")) {
            return "-type-js";
        } else if (simpleType.matches("html|xml")) {
            return "-type-html";
        }
        return "-type-generic";
    }

	public String getStyle() {
        return "image" + getStyleType();
	}
	
	public String getBarStyle() {
		return "bar" + getStyleType();
	}
	
	public Traffic getMe() {
		return this;
	}

	public String getName() {
		return name;
	}

	public Instant getStartTime() {
		return startTime;
	}

	public Instant getEndTime() {
		return endTime;
	}

	public String getPath() {
		return path;
	}

	public String getMethod() {
		return method;
	}

	public Integer getStatusCode() {
		return statusCode;
	}

	public String getStatusText() {
		return statusText;
	}

	public String getType() {
		return type;
	}

	public String getInitiator() {
		return initiator;
	}

	public String getSize() {
		return size;
	}

    public Duration getDuration() {
        return Duration.between(startTime, endTime);
    }

	public String getTime() {
        String timeSpan;
        Duration d = Duration.between(startTime, endTime);

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

        return timeSpan;
    }

	public boolean isError() {
		return getStatusCode() >= 400;
	}
}
