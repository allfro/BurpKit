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


if ('contextMenuFactory' in window) {
    alert('Unregistering old context menu factory.');
    burpCallbacks.removeContextMenuFactory(contextMenuFactory);
}

alert('Registering new context menu factory!');
contextMenuFactory = burpCallbacks.registerContextMenuFactory(function(invocation){

    burpCallbacks.issueAlert(
        'Context menu factory invoked from ' +
        burpCallbacks.getToolName(invocation.getToolFlag())
    );

    return [
        burpKit.createJMenuItem(
            'Say "Hello World!"',
            function(event) {burpCallbacks.issueAlert('Hello World!');}
        )
    ];

});