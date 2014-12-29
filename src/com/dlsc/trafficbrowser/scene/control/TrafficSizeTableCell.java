package com.dlsc.trafficbrowser.scene.control;


import com.dlsc.trafficbrowser.beans.Traffic;

public class TrafficSizeTableCell extends TrafficTableCellBase {
		
	public TrafficSizeTableCell() {
	}
	
	@Override
	protected String lookupText1(Traffic traffic) {
		return getItem().getSize();
	}
}
