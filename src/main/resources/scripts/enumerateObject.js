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
 * Created by ndouba on 15-06-23.
 */

(function(__burpKitIntroSpectionVariable) {
    var __burpKitResultVariable = {};


    for (var __burpKitKeyNameVariable in __burpKitIntroSpectionVariable) { __burpKitResultVariable[__burpKitKeyNameVariable] = true; }

    Object.getOwnPropertyNames(__burpKitIntroSpectionVariable).forEach(
        function(__burpKitKeyNameVariable) {__burpKitResultVariable[__burpKitKeyNameVariable] = true;}
    );

    Object.keys(__burpKitIntroSpectionVariable).forEach(
        function(__burpKitKeyNameVariable) {__burpKitResultVariable[__burpKitKeyNameVariable] = true;}
    );

    try {
        Object.getOwnPropertyNames(__burpKitIntroSpectionVariable).forEach(
            function(__burpKitKeyNameVariable) {__burpKitResultVariable[__burpKitKeyNameVariable] = true;}
        );
    } catch (__burpKitIgnoredExceptionVariable) {
        Object.getOwnPropertyNames(Object.getPrototypeOf(__burpKitIntroSpectionVariable)).forEach(
            function(__burpKitKeyNameVariable) {__burpKitResultVariable[__burpKitKeyNameVariable] = true;}
        );
    }

    return Object.keys(__burpKitResultVariable);
})(%s);