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
 * The following example demonstrates how to create a payload processor
 * for intruder. In this example, we'll be using ROT13 on the current
 * payload. In order to run this example, go to the Intruder 'Payloads'
 * tab and click the 'Add' button under 'Payload Processing'. Select
 * 'Invoke Burp extension' from the 'Select rule type' drop-down menu.
 * Select 'ROT13 Processor' from the second drop-down menu and click
 * 'OK'. Run your attack and enjoy the magic :)
 */

burpKit.requireLib("rotlib");

if ('processorFactory' in window) {
    alert('Unregistering old intruder payload processor factory.');
    burpCallbacks.removeIntruderPayloadGeneratorFactory(processorFactory);
}

alert('Registering new intruder payload processor factory!');
processorFactory = burpCallbacks.registerIntruderPayloadGeneratorFactory({
    'getProcessorName': function() {
        return "ROT13 Processor";
    },
    'processPayload': function(currentPayload, originalPayload, baseValue) {
        return rotlib.rot(burpCallbacks.getHelpers().bytesToString(currentPayload), 13);
    }
});