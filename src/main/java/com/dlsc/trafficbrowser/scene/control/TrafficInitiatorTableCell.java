package com.dlsc.trafficbrowser.scene.control;


import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficInitiatorTableCell extends TrafficTableCellBase {
		
	public TrafficInitiatorTableCell() {
	}
	
	@Override
	protected String lookupText1(Traffic traffic) {
		return getItem().getInitiator();
	}
}
