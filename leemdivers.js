// Define hosts
const originalHost = "https://api.live.prod.thehelldiversgame.com/";
const replacementHost = "https://leemdivers-api-static.pages.dev/";

function isTargetUrl(url) {
    return url.indexOf(originalHost) === 0;
}

function replaceUrl(url) {
    return url.replace(originalHost, replacementHost);
}

// Find the curl_easy_setopt function
const libcurl = Process.getModuleByName("libcurl.dll");
const curl_easy_setopt = Module.getExportByName("libcurl.dll", "curl_easy_setopt");

// Hook into curl_easy_setopt
Interceptor.attach(curl_easy_setopt, {
    onEnter: function (args) {
        const CURLOPT_URL = 10002;
        if (parseInt(args[1]) === CURLOPT_URL) {
            const urlPtr = args[2];
            const url = Memory.readUtf8String(urlPtr);
            if (isTargetUrl(url)) {
                const newUrl = replaceUrl(url);
                console.log("[Frida] Redirecting", url, "to", newUrl);
                Memory.writeUtf8String(urlPtr, newUrl);
            }
        }
    }
});
