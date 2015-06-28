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

/**
 * The following example demonstrates how to create a payload generator
 * for intruder. In this example, we'll be generating ten random UUIDs.
 * In order to run this generator, you'll need to select 'Extension-
 * generated' from the 'Payloads' tab under the 'Payload type' drop-
 * down menu. Once you've selected this option, a button with the label
 * 'Select generator...' will appear. Click on that button and select
 * 'UUID Generator' from the 'Extension payload generator' drop-down and
 * click 'OK'. Finally, start your attack and enjoy the magic :)
 */

if ('payloadFactory' in window) {
    alert('Unregistering old intruder payload generator factory.');
    burpCallbacks.removeIntruderPayloadGeneratorFactory(payloadFactory);
}

function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
            .toString(16)
            .substring(1);
    }
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
        s4() + '-' + s4() + s4() + s4();
}

function UUIDGenerator() {
    this.maxRequests = 10;
    this.numRequests = 0;
}

UUIDGenerator.prototype = {
   'hasMorePayloads': function() {
        return this.maxRequests != this.numRequests;
    },
    'getNextPayload': function(baseValue) {
        this.numRequests++;
        return guid();
    },
    'reset': function() {
        this.numRequests = 0;
    }
};

alert('Registering new intruder payload generator factory!');
payloadFactory = burpCallbacks.registerIntruderPayloadGeneratorFactory({
    'getGeneratorName': function() { return "UUID Generator"; },
    'createNewInstance': function(attack) {
        return new UUIDGenerator();
    }
});