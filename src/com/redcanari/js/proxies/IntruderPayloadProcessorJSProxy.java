package com.redcanari.js.proxies;

import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadProcessor;
import netscape.javascript.JSObject;

/**
 * Created by ndouba on 14-12-09.
 */
public class IntruderPayloadProcessorJSProxy extends JSProxy implements IIntruderPayloadProcessor {

    public IntruderPayloadProcessorJSProxy(JSObject jsObject) {
        super(jsObject);
    }

    @Override
    public String getProcessorName() {
        return null;
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        return new byte[0];
    }
}
