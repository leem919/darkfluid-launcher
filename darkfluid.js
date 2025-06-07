const originalHost = "https://api.live.prod.thehelldiversgame.com/";
const replacementHost = "https://darkfluid-api.vercel.app/";
const dummyHost = "https://dummyjson.com/posts";

const endpointsToDummy = [
    "/api/FriendsV2/Block",
    "/api/Operation/Abandon",
    "/api/Monetization/Steam/RedeemStoreContent",
    "/api/Progression/Items/Customize",
    "/api/Stats/profile/summary",
    "/api/Stats/profile/801/summary",
    "/api/Stats/war/801/summary",
    "/api/v2/Assignment/Player",
    "/api/LeaderBoard/MiniGame/4171714171",
    "/api/lobby",
    "/api/Mail/inbox",
    "/api/Account/ReportPosition",
    "/api/Operation/Create",
    "/api/Operation/Mission/Start",
    "/api/SeasonPass/1929468580",
    "/api/storefront",
    "/api/storefront/rotation",
    "/api/Operation/Mission/SetMaxRewards",
    "/api/Progression/inventory/consume",
    "/api/Progression/Achievements"

];

const libcurlModule = Process.platform === 'windows' ? "libcurl.dll" : "libcurl.so";
const curl_easy_setopt = Module.getExportByName(libcurlModule, "curl_easy_setopt");

Interceptor.attach(curl_easy_setopt, {
    onEnter: function (args) {
        const CURLOPT_URL = 10002;
        const option = args[1].toInt32();

        if (option === CURLOPT_URL) {
            const urlPtr = args[2];
            const originalUrl = Memory.readUtf8String(urlPtr);

            if (originalUrl.startsWith(originalHost)) {
                let isDummyEndpoint = false;

                // Check if it's a specific endpoint for the dummy host
                const path = originalUrl.substring(originalHost.length - 1);
                
                for (const endpoint of endpointsToDummy) {
                    if (path.startsWith(endpoint)) {
                        // This is a specific endpoint. Redirect to the dummy host.
                        const newUrl = dummyHost + path;
                        console.log(`Redirecting to: ${newUrl}`);
                        Memory.writeUtf8String(urlPtr, newUrl);
                        isDummyEndpoint = true;
                        break; // Exit the loop
                    }
                }

                // Perform the general redirection
                if (!isDummyEndpoint) {
                    const newUrl = originalUrl.replace(originalHost, replacementHost);
                    console.log(`Redirecting to: ${newUrl}`);
                    Memory.writeUtf8String(urlPtr, newUrl);
                }
            }
        }
    }
});
