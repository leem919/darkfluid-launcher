// Define hosts
const originalHost = "https://api.live.prod.thehelldiversgame.com/";
const replacementHost = "https://leemdivers-api-bxra.onrender.com/";

const deniedEndpoints = [
    "https://api.live.prod.thehelldiversgame.com/api/FriendsV2/Block",
    "https://api.live.prod.thehelldiversgame.com/api/Progression/Items/Customize",
    "https://api.live.prod.thehelldiversgame.com/api/Monetization/Steam/RedeemStoreContent",
    "https://api.live.prod.thehelldiversgame.com/api/Stats/profile/summary",
    "https://api.live.prod.thehelldiversgame.com/api/Stats/profile/801/summary",
    "https://api.live.prod.thehelldiversgame.com/api/Stats/war/801/summary",
    "https://api.live.prod.thehelldiversgame.com/api/LeaderBoard/MiniGame/4171714171",
    "https://api.live.prod.thehelldiversgame.com/api/Mail/inbox",
    "https://api.live.prod.thehelldiversgame.com/api/v2/Assignment/Player",
    "https://api.live.prod.thehelldiversgame.com/api/Operation/Create",
    "https://api.live.prod.thehelldiversgame.com/api/Account/ReportPosition",
    "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/Start",
    "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/SetMaxRewards",
    "https://api.live.prod.thehelldiversgame.com/api/Progression/inventory/consume",
    "https://api.live.prod.thehelldiversgame.com/api/Progression/Achievements"
];

function isTargetUrl(url) {
    return url.indexOf(originalHost) === 0;
}

function replaceUrl(url) {
    return url.replace(originalHost, replacementHost);
}

function isDeniedEndpoint(url) {
    return deniedEndpoints.some(endpoint => url.startsWith(endpoint));
}

// Find the curl_easy_setopt function
const libcurl = Process.getModuleByName("libcurl.dll");
const curl_easy_setopt = Module.getExportByName("libcurl.dll", "curl_easy_setopt");

// Hook into curl_easy_setopt
Interceptor.attach(curl_easy_setopt, {
    onEnter: function (args) {
        // CURLOPT_URL is usually 10002
        const CURLOPT_URL = 10002;
        if (parseInt(args[1]) === CURLOPT_URL) {
            const urlPtr = args[2];
            const url = Memory.readUtf8String(urlPtr);

            // Deny/block requests to specific endpoints
            if (isDeniedEndpoint(url)) {
                console.log("Blocking", url);
                this.returnValue = ptr(3);
                return;
            }

            if (isTargetUrl(url)) {
                const newUrl = replaceUrl(url);
                console.log("Redirecting", url, "to", newUrl);
                Memory.writeUtf8String(urlPtr, newUrl);
            }
        }
    }
});
