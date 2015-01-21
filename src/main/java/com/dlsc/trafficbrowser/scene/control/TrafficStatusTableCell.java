package com.dlsc.trafficbrowser.scene.control;


import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficStatusTableCell extends TrafficTableCellBase {
		
	public TrafficStatusTableCell() {
	}
	
	@Override
	protected String lookupText1(Traffic traffic) {
		return getItem().getStatusCode().toString();
	}
	
	@Override
	protected String lookupText2(Traffic traffic) {
		return getItem().getStatusText();
	}
}
