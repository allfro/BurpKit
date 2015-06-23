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
 * Created by ndouba on 15-01-01.
 */

(function(F, i, r, e, b, u, g, L, I, T, E) {
    if(F.getElementById(b))
        return;
    E = F[i+'NS'] && F.documentElement.namespaceURI;
    E = E?F[i+'NS'](E,'script'):F[i]('script');
    E[r]('id',b);
    E[r]('src',I+g+T);
    E[r](b,u);
    (F[e]('head')[0] || F[e]('body')[0]).appendChild(E);
    E = new Image;E[r]('src',I+L);
})(
    document,
    'createElement',
    'setAttribute',
    'getElementsByTagName',
    'FirebugLite',
    '4',
    'firebug-lite.js',
    'skin/xp/sprite.png',
    'burp:///web/firebug/',
    '#startOpened'
);