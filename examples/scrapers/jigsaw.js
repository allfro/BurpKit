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
 * In this example we'll scrape LinkedIn profiles for employees fitting
 * our specific search criteria. First we manually navigate to LinkedIn
 * and perform our query. Once we've received our results, run this
 * script to scape the profiles.
 */

// Load our CSV library.
burpKit.requireLib('csvlib');

// Ask the user where they want to save the scraping results.
if (!('outputFile' in this) || outputFile == null)
	outputFile = burpKit.saveFileDialog('Save results to...');

main();

function main() {
	var data = [];

	var titles = $j('.td-title');
	var names = $j('.td-name');

	var num = Math.min(titles.length, names.length);
	// Find all profiles and extract title and description.
	for (var i = 0; i < num; i++) {
		var fullName = names[i].innerText;
		var description = titles[i].innerText;
		data.push([fullName, description]);
	};

	// Conver the data extracted into comma separated value format and
	// write to file.
	csvlib.stringify(data, function(error, data) {
		burpKit.appendToFile(outputFile, data);
	});
}