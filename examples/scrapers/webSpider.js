/**
 * The following example demonstrates how to create a crawl loop using the `window.onload` event
 * as a trigger. By toggling on the red refresh button on the bottom left-hand corner of any
 * BurpScript IDE tab, the following script will be executed everytime a new page is loaded.
 * In this example, we introduce a couple of cool features that come with BurpKit:
 *
 * 	1. Writing data to files using the `burpKit.appendToFile()` function.
 *	2. Using the `locals` variable that provides access to a ConcurrentHashMap that survives
 *         across page loads but is local to this BurpKit IDE instance.
 */

// Let's create some variables to maintain our spider state. Here we use `loopCount` as a guard
// variable for initialization and loop counting.
var locals = burpKit.locals();
var re = /(aspx?|jspx?|html?|phpx|\/([^\.]+)?)$/; 
var loopCount = locals.getOrDefault('loopCount', 0);

// `urlsCrawled` and `urlsToCrawl` will track the links we've already crawled and the links we
// need to crawl, respectively. We use JSON to retrieve our crawl queue state because `locals` only
// supports primitive data types suchs as strings, integers, floats, and booleans.
var urlsCrawled = JSON.parse(locals.getOrDefault('urlsCrawled', '{}'));
var urlsToCrawl = JSON.parse(locals.getOrDefault('urlsToCrawl', '[]'));

// `wordListFile` is where we'll write our wordlist to on the filesystem.
var wordListFile = burpKit.pathJoin(burpKit.homeDirectory(), ['wordlist.txt']);

// `isInCrawlQueue` checks to see whether or not a link has already been visited or is in the crawl
// queue.
function isInCrawlQueue(url) {
    return (urlsToCrawl.indexOf(url) != -1 || url in urlsCrawled);
}

// `saveState` is called before navigating to the next page to update the `loopCount` as well as the
// state of the crawl queue.
function saveState() {
	locals.put('loopCount', loopCount + 1); 
	locals.put('urlsCrawled', JSON.stringify(urlsCrawled)); 
	locals.put('urlsToCrawl', JSON.stringify(urlsToCrawl));
}

// `saveText` extract `document.body.innerText`, trims whitespace, splits it using newlines and
// whitespace as delimeters, and finally writes the output to the wordlist file.
function saveText(fileName) {
	alert('Saving text: ' + document.body.innerText);
	burpKit.appendToFile(fileName, document.body.innerText.trim().split(/[\s\n]+/).join('\n'));
}


// If we've just started looping, we will initialize our state and navigate to our first URL.
if (!loopCount) {
	saveState();
	document.location = prompt("Which site would you like to crawl?");
} else {
	// mark URL as crawled in crawl queue
	urlsCrawled[document.location] = 1; 

	alert('Extracting links from ' + document.location);

	// Save words to file.
	saveText(wordListFile); 

	// extract hyperlinks from current page.
	var hrefs = document.body.getElementsByTagName('a'); 

	alert('Discovered ' + hrefs.length + ' hyperlinks.');
	for (var i = 0; i < hrefs.length; i++) {
		// extract URL without fragment identifier.
		var link = hrefs[i].href.split('#', 2)[0]; 

		// Check if URL is HTTP-based and has not been visited or in crawl queue before adding to crawler.
		if (link.indexOf('http') == 0 && re.test(link) && burpCallbacks.isInScope(link) && !isInCrawlQueue(link)) {
			alert('Adding ' + link + ' to crawl queue.'); 
			urlsToCrawl.push(link);
		}
	}
	
	// Get the next location from our crawl queue.
	var nextLocation = urlsToCrawl.pop();
	
	// Save our crawl state.
	saveState();

	// If `nextLocation` is defined then we have a page to crawl. Otherwise, we have nothing left to crawl.
	if (nextLocation != undefined) {
		alert('Navigating to ' + nextLocation + ' in 3 seconds');
		window.setTimeout(function() {document.location = nextLocation;}, 3000);
	} else {
		alert('Finished crawling ' + loopCount + ' pages!');
	}
}