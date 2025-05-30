// Define addresses
const originalHost = "https://api.live.prod.thehelldiversgame.com/";
const replacementHost = "https://dancing-starlight-d55eb8.netlify.app/";
const loginEndpoint = "https://api.live.prod.thehelldiversgame.com/api/Account/Login";
const loginRedirect = "https://dummyjson.com/c/3029-d29f-4014-9fb4";

function getRedirectUrl(url) {
    if (url === loginEndpoint) {
        return loginRedirect;
    } else if (url.indexOf(originalHost) === 0) {
        return url.replace(originalHost, replacementHost);
    }
    return null;
}

// Hook into curl_easy_setopt
const libcurl = Process.getModuleByName("libcurl.dll");
const curl_easy_setopt = Module.getExportByName("libcurl.dll", "curl_easy_setopt");

Interceptor.attach(curl_easy_setopt, {
    onEnter: function (args) {
        const CURLOPT_URL = 10002;
        if (parseInt(args[1]) === CURLOPT_URL) {
            const urlPtr = args[2];
            const url = Memory.readUtf8String(urlPtr);
            const newUrl = getRedirectUrl(url);
            if (newUrl) {
                console.log("[Frida] Redirecting", url, "to", newUrl);
                Memory.writeUtf8String(urlPtr, newUrl);
            }
        }
    }
});
