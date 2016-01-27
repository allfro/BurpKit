/**
 * In this example we demonstrate how to scrape Twitter followers using the official website
 * (not the API). A lot of times websites don't offer an API or render content dynamically
 * via a series of background AJAX/web service calls. The Twitter followers page is a good
 * example where AJAX is used to incrementally load a user's followers on the page as the
 * user scrolls downward. Here we will use a combination of JavaScript and the BurpKit API
 * to log us into Twitter, select the user being targeted, and finally write the output to
 * a CSV file.
 */

var locals = burpKit.locals();

// The screen name of the Twitter user we will be targeting.
var targetUser = locals.getOrDefault('targetUser', '');

// The URL of our target user's followers page.
var targetUrl = 'https://twitter.com/' + targetUser + '/followers';

// We use a loop counter to track our scraper's state.
var loopCount = locals.getOrDefault('loopCount', 0);

switch (loopCount) {
	case 0:
		goToFollowers();
		break;
	case 1:
		login();
		break;
	case 2:
		extractFollowers();
}

// Ask which Twitter handle to scrape and go to their followers page.
function goToFollowers() {
	// `prompt()` provides a dialog box with a single text field for input.
	targetUser = prompt('Which Twitter user would you like to scrape?');

	// persist our `targetUser` and `loopCount` so that we can retrieve it over page navigations.
	locals.put('targetUser', targetUser);
	locals.put('loopCount', loopCount + 1);

	// Go to the Twitter user's followers page.
	document.location = 'https://twitter.com/' + targetUser + '/followers';
}

function login() {
	// if we are already at the Twitter user's followers page then we have already logged in.
	if (document.location == targetUrl) {
		// Start scraping if we've already logged in.
		extractFollowers();
		return;
	}

	// Otherwise, let's prompt the user for their Twitter credentials and login to Twitter.
	burpKit.loginPrompt(function(username, password) {
		// Here we are leveraging jQuery to select, fill, and submit the login form.
		// Luckily Twitter has already included jQuery as part of the page. 
		var form = $('form.signin')[0];
		$('[name="session[username_or_email]"]', form)[0].value = username;
		$('[name="session[password]"]', form)[0].value = password;
		locals.put('loopCount', loopCount + 1);
		form.submit();
	});
}

function extractFollowers() {
	// if our current URL is not the followers page then we probably failed to login.
	if (document.location != targetUrl) {
		alert('Login failed!');
		locals.clear();
		return;
	}

	var followerCount = 0;
		
	// Otherwise, we use a timer to scroll to the bottom of the page every second to load
	// all the user's followers in one page.
	var timer = window.setInterval(function() {

		// Get all the Twitter followers
		var followers = $('.ProfileCard');

		// If our current follower count is greater than the previous, then continue scrolling
		if (followers.length != followerCount) {
			followerCount = followers.length;
			window.scrollTo(0, document.body.scrollHeight);
		} else {
			// Otherwise, stop scrolling and save results.
			window.clearInterval(timer);
			alert('Found ' + followers.length + ' followers!');
			saveFollowers(followers);
		}

	}, 1000);
	
	locals.clear();
}

function saveFollowers(followers) {
	// Our output CSV file.
	var followersFile = burpKit.saveFileDialog('Save CSV file...');

	alert('Writing results to ' + followersFile);

	// we load the CSV library (`csvlib`) into our DOM. `burpKit.requireLib()` loads the specified library
	// into the DOM by assigning it to a variable of the same name (i.e. `csvlib.stringify()`).
	this.burpKit.requireLib('csvlib');

	// Setup our CSV header row
	var data = new Array(["Name", "Screen Name", "Verified", "Bio", "Profile Link"]);

	// Loop through our followers and extract the name, screen name, verified status, bio, and profile link
	for (var i = 0; i < followers.length; i++) {
		var follower = followers[i];
		screenName = '@' + follower.attributes['data-screen-name'].value;
		profileLink = 'https://twitter.com/' + screenName;
		fullName = ($('.fullname', follower)[0] || $('.js-action-profile-name', follower)[0]).innerText
		verified = $('[href="/help/verified"]', follower).length == 1;
		bio = $('.ProfileCard-bio', follower)[0].innerText;
		data.push([fullName, screenName, verified, bio, profileLink]);
	}

	// Once we've extracted all our data, we write it out to a CSV file.
	csvlib.stringify(data, function(err, output) {burpKit.writeToFile(followersFile, output);});
}