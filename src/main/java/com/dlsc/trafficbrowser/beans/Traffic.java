package com.dlsc.trafficbrowser.beans;

import java.time.Instant;

public class Traffic {

	private String name;
	private String path;
	private String method;
	private Integer statusCode;
	private String statusText;
	private String type;
	private String initiator;
	private String size;

	private final Instant startTime;

	private final Instant endTime;

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

	public String getStyle() {
		switch (getType()) {
			case "text/html":
				return "image-type-html";
			case "text/javascript":
				return "image-type-js";
			case "text/css":
				return "image-type-css";
			default:
				return "image-type-generic";
		}
	}
	
	public String getBarStyle() {
		switch (getType()) {
			case "text/html":
				return "bar-type-html";
			case "text/javascript":
				return "bar-type-js";
			case "text/css":
				return "bar-type-css";
			default:
				return "bar-type-generic";
		}
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

	public String getTime() {
		return (getEndTime().toEpochMilli() - getStartTime().toEpochMilli()) + " ms";
	}

	public boolean isError() {
		return getStatusCode() >= 400;
	}
}
