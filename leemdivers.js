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
// Adjust "libcurl.dll" if on a different OS (e.g., "libcurl.so" or "libcurl.dylib")
const libcurlModule = Process.getModuleByName("libcurl.dll");
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
                url: "",
                isDenied: false,
                originalWriteFunction: null,
                originalWriteData: ptr(0), // Default to NULL if not set
                originalHeaderFunction: null,
                originalHeaderData: ptr(0) // Default to NULL if not set
            };
            curlHandlesDetails.set(curlHandleStr, handleData);
        }

        switch (option) {
            case CURLOPT_URL:
                const urlPtr = args[2];
                const url = Memory.readUtf8String(urlPtr);
                handleData.url = url;
                // console.log("Frida: curl_easy_setopt(CURLOPT_URL, \"" + url + "\") for handle " + curlHandleStr);

                if (isDeniedEndpoint(url)) {
                    console.log("Faking OK to: " + url);
                    handleData.isDenied = true;
                    // Do NOT modify URL or return error; let setopt succeed.
                } else if (isTargetUrl(url)) {
                    const newUrl = replaceUrl(url);
                    console.log("Redirecting", url, "to", newUrl);
                    Memory.writeUtf8String(urlPtr, newUrl);
                    handleData.isDenied = false;
                } else {
                    handleData.isDenied = false;
                }
                break;
            case CURLOPT_WRITEFUNCTION:
                // console.log("[+] Frida: curl_easy_setopt(CURLOPT_WRITEFUNCTION) for handle " + curlHandleStr);
                handleData.originalWriteFunction = args[2];
                break;
            case CURLOPT_WRITEDATA:
                // console.log("[+] Frida: curl_easy_setopt(CURLOPT_WRITEDATA) for handle " + curlHandleStr);
                handleData.originalWriteData = args[2];
                break;
            case CURLOPT_HEADERFUNCTION:
                // console.log("[+] Frida: curl_easy_setopt(CURLOPT_HEADERFUNCTION) for handle " + curlHandleStr);
                handleData.originalHeaderFunction = args[2];
                break;
            case CURLOPT_HEADERDATA:
                // console.log("[+] Frida: curl_easy_setopt(CURLOPT_HEADERDATA) for handle " + curlHandleStr);
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

        if (handleData && handleData.isDenied) {
            console.log("[+] Frida: curl_easy_perform for DENIED URL: " + handleData.url + ". Intercepting and faking 200 OK response.");

            // Replace the original curl_easy_perform with our fake function
            this.replace(new NativeCallback((easyHandlePtr) => {
                const currentHandleData = curlHandlesDetails.get(easyHandlePtr.toString());
                if (!currentHandleData) {
                    console.error("[-] Frida Error: No handle data in fakePerform for " + easyHandlePtr.toString());
                    return 1; // CURLE_FAILED_INIT or another relevant error code
                }

                console.log("[+] Frida: Executing fake_perform for " + currentHandleData.url);

                // 1. Simulate delivering fake headers via the application's header callback
                if (currentHandleData.originalHeaderFunction && !currentHandleData.originalHeaderFunction.isNull()) {
                    const fakeHeaders = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\n"; // Length of "status: success" is 15
                    const fakeHeadersPtr = Memory.allocUtf8String(fakeHeaders);
                    try {
                        const headerCb = new NativeFunction(currentHandleData.originalHeaderFunction, 'size_t', ['pointer', 'size_t', 'size_t', 'pointer']);
                        headerCb(fakeHeadersPtr, 1, fakeHeaders.length, currentHandleData.originalHeaderData);
                        console.log("[+] Frida: Fake headers delivered via originalHeaderFunction.");
                    } catch (e) {
                        console.error("[-] Frida Error calling originalHeaderFunction: " + e.message);
                    }
                } else {
                    console.log("[+] Frida: No originalHeaderFunction set by the application for " + currentHandleData.url);
                }

                // 2. Simulate delivering fake body via the application's write callback
                if (currentHandleData.originalWriteFunction && !currentHandleData.originalWriteFunction.isNull()) {
                    const fakeBody = "status: success";
                    const fakeBodyPtr = Memory.allocUtf8String(fakeBody);
                    try {
                        const writeCb = new NativeFunction(currentHandleData.originalWriteFunction, 'size_t', ['pointer', 'size_t', 'size_t', 'pointer']);
                        writeCb(fakeBodyPtr, 1, fakeBody.length, currentHandleData.originalWriteData);
                        console.log("[+] Frida: Fake body 'status: success' delivered via originalWriteFunction.");
                    } catch (e) {
                        console.error("[-] Frida Error calling originalWriteFunction: " + e.message);
                    }
                } else {
                    console.log("[+] Frida: No originalWriteFunction set by the application for " + currentHandleData.url + ". Fake body not delivered via callback.");
                    // Note: If the app relies on libcurl's default behavior (writing to stdout)
                    // and doesn't set a write callback, this fake body won't appear on stdout.
                }

                return CURLE_OK; // Return 0 to indicate success
            }, 'int', ['pointer'])); // curl_easy_perform returns CURLcode (int) and takes (CURL *easy_handle)
        } else if (handleData) {
            // console.log("[+] Frida: curl_easy_perform for allowed/redirected URL: " + handleData.url);
        } else {
            // console.log("[+] Frida: curl_easy_perform for an untracked handle: " + curlHandleStr);
        }
    },
    onLeave: function (retval) {
        // This onLeave is primarily for requests that were NOT replaced.
        // For replaced requests, the NativeCallback's return in onEnter is the final return.
        // const curlHandle = this.context.handle; // Need to save handle in onEnter if used here
        // console.log("[+] Frida: curl_easy_perform finished with retval: " + retval.toInt32());
    }
});

console.log("Frida script for leemdiversapi is active.");