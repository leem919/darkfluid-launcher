// Define hosts
const originalHost = "https://api.live.prod.thehelldiversgame.com/";
const replacementHost = "https://dancing-starlight-d55eb8.netlify.app/";

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
    "https://api.live.prod.thehelldiversgame.com/api/Account/Login"
];

// Store data per curl handle
const curlHandlesDetails = new Map();

// libcurl constants
const CURLOPT_URL = 10002;
const CURLOPT_WRITEFUNCTION = 20011;
const CURLOPT_WRITEDATA = 10001;
const CURLOPT_HEADERFUNCTION = 20079;
const CURLOPT_HEADERDATA = 10029;
const CURLE_OK = 0;

// Helper functions
function isTargetUrl(url) {
    return url.startsWith(originalHost);
}

function replaceUrl(url) {
    return url.replace(originalHost, replacementHost);
}

function isDeniedEndpoint(url) {
    return deniedEndpoints.some(endpoint => url.startsWith(endpoint));
}

// Get libcurl module and functions
const libcurlModule = Process.getModuleByName("libcurl.dll"); // Adjust for your OS if needed
const curl_easy_setopt_ptr = libcurlModule.getExportByName("curl_easy_setopt");
const curl_easy_perform_ptr = libcurlModule.getExportByName("curl_easy_perform");

Interceptor.attach(curl_easy_setopt_ptr, {
    onEnter: function (args) {
        const curlHandle = args[0];
        const option = parseInt(args[1]);
        const curlHandleStr = curlHandle.toString();

        let handleData = curlHandlesDetails.get(curlHandleStr);
        if (!handleData) {
            handleData = {
                url: "", // URL actually set on the handle (original, redirected, or dummy)
                initialUrl: "", // URL as first seen by setopt for this call
                isDenied: false,
                originalDeniedUrl: null, // Stores the true original URL if it was denied
                originalWriteFunction: null,
                originalWriteData: ptr(0),
                originalHeaderFunction: null,
                originalHeaderData: ptr(0)
            };
            curlHandlesDetails.set(curlHandleStr, handleData);
        }
        // Store handle string in context for easier access in logs if needed, not strictly necessary here
        // this.curlHandleStr = curlHandleStr;

        switch (option) {
            case CURLOPT_URL: {
                const urlPtr = args[2];
                const currentUrlInOpt = Memory.readUtf8String(urlPtr);
                handleData.initialUrl = currentUrlInOpt; // Record the URL passed to this specific setopt call

                if (isDeniedEndpoint(currentUrlInOpt)) {
                    console.log(`[+] Frida: Denied endpoint for handle ${curlHandleStr}: ${currentUrlInOpt}. Will be faked. Changing URL to dummy.`);
                    handleData.isDenied = true;
                    handleData.originalDeniedUrl = currentUrlInOpt; // Store the actual original denied URL
                    
                    // Dummy URL that won't go to the external network.
                    const dummyUrl = `https://dummyjson.com/c/3029-d29f-4014-9fb4`;
                    
                    Memory.writeUtf8String(urlPtr, dummyUrl);
                    handleData.url = dummyUrl; // Update the URL tracked in handleData to the dummy one
                    console.log(`[+] Frida: URL for handle ${curlHandleStr} (original: ${currentUrlInOpt}) changed to dummy: ${dummyUrl}.`);
                } else {
                    // If it's not a denied endpoint, ensure denied status is cleared for this handle (in case of reuse)
                    if (handleData.isDenied) {
                        // console.log(`[+] Frida: Handle ${curlHandleStr} was previously denied, now set to non-denied URL: ${currentUrlInOpt}. Clearing denied status.`);
                        handleData.isDenied = false;
                        handleData.originalDeniedUrl = null;
                    }

                    if (isTargetUrl(currentUrlInOpt)) { // Check if current URL (not a denied one) is a target for redirection
                        const newRedirectedUrl = replaceUrl(currentUrlInOpt);
                        console.log(`[+] Frida: Redirecting for handle ${curlHandleStr}: ${currentUrlInOpt} to ${newRedirectedUrl}`);
                        Memory.writeUtf8String(urlPtr, newRedirectedUrl);
                        handleData.url = newRedirectedUrl;
                    } else {
                        handleData.url = currentUrlInOpt; // Store the URL as is if not denied and not redirected
                    }
                }
                break;
            }
            case CURLOPT_WRITEFUNCTION:
                handleData.originalWriteFunction = args[2];
                break;
            case CURLOPT_WRITEDATA:
                handleData.originalWriteData = args[2];
                break;
            case CURLOPT_HEADERFUNCTION:
                handleData.originalHeaderFunction = args[2];
                break;
            case CURLOPT_HEADERDATA:
                handleData.originalHeaderData = args[2];
                break;
        }
    }
});

Interceptor.attach(curl_easy_perform_ptr, {
    onEnter: function (args) {
        const curlHandle = args[0];
        const curlHandleStr = curlHandle.toString();
        const handleData = curlHandlesDetails.get(curlHandleStr);

        let logUrlForPerform = handleData ? (handleData.originalDeniedUrl || handleData.url) : "N/A (no handleData)";
        // console.log(`[+] Frida: curl_easy_perform for handle ${curlHandleStr}. Effective URL: ${logUrlForPerform}. Denied flag: ${handleData ? handleData.isDenied : 'N/A'}`);

        if (handleData && handleData.isDenied) {
            const originalDeniedUrlForLog = handleData.originalDeniedUrl || handleData.initialUrl; // Prefer originalDeniedUrl for clarity
            console.log(`[+] Frida: curl_easy_perform for DENIED original URL: ${originalDeniedUrlForLog} (handle ${curlHandleStr}). Intercepting with fake_perform.`);

            this.replace(new NativeCallback((easyHandlePtr) => {
                const currentHandleData = curlHandlesDetails.get(easyHandlePtr.toString());
                if (!currentHandleData) {
                    console.error(`[-] Frida Error: No handle data in fakePerform for ${easyHandlePtr.toString()}`);
                    return 1; // CURLE_FAILED_INIT or some other error code
                }

                const logUrl = currentHandleData.originalDeniedUrl || currentHandleData.initialUrl; // URL for logging
                console.log(`[+] Frida: Executing fake_perform for original URL: ${logUrl}`);

                // 1. Simulate delivering fake headers
                if (currentHandleData.originalHeaderFunction && !currentHandleData.originalHeaderFunction.isNull()) {
                    const fakeHeaders = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\n"; // Length of "status: success"
                    const fakeHeadersPtr = Memory.allocUtf8String(fakeHeaders);
                    try {
                        const headerCb = new NativeFunction(currentHandleData.originalHeaderFunction, 'size_t', ['pointer', 'size_t', 'size_t', 'pointer']);
                        headerCb(fakeHeadersPtr, 1, fakeHeaders.length, currentHandleData.originalHeaderData);
                        // console.log("[+] Frida: Fake headers delivered via originalHeaderFunction.");
                    } catch (e) {
                        console.error(`[-] Frida Error calling originalHeaderFunction for ${logUrl}: ${e.message}`);
                    }
                } else {
                    // console.log(`[+] Frida: No originalHeaderFunction set by app for ${logUrl} to deliver fake headers.`);
                }

                // 2. Simulate delivering fake body
                if (currentHandleData.originalWriteFunction && !currentHandleData.originalWriteFunction.isNull()) {
                    const fakeBody = "status: success";
                    const fakeBodyPtr = Memory.allocUtf8String(fakeBody);
                    try {
                        const writeCb = new NativeFunction(currentHandleData.originalWriteFunction, 'size_t', ['pointer', 'size_t', 'size_t', 'pointer']);
                        writeCb(fakeBodyPtr, 1, fakeBody.length, currentHandleData.originalWriteData);
                        // console.log("[+] Frida: Fake body 'status: success' delivered via originalWriteFunction.");
                    } catch (e) {
                        console.error(`[-] Frida Error calling originalWriteFunction for ${logUrl}: ${e.message}`);
                    }
                } else {
                    // console.log(`[+] Frida: No originalWriteFunction set by app for ${logUrl}. Fake body not delivered via callback.`);
                }
                return CURLE_OK;
            }, 'int', ['pointer']));
        } else if (handleData) {
            // console.log(`[+] Frida: curl_easy_perform for ALLOWED/REDIRECTED URL: ${handleData.url} (handle ${curlHandleStr}). Proceeding with original call.`);
        } else {
            console.warn(`[-] Frida: curl_easy_perform for untracked handle: ${curlHandleStr}. No handleData found. Proceeding with original call.`);
        }
    }
});

console.log("[+] Frida script for libcurl is active.");
console.log("[+] Denied endpoint URLs changed to dummy. No external connection will be made.");
console.log("[+] Other matching API calls will be redirected to: " + replacementHost);
