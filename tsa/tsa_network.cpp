///
// Created by axjp on 25/06/2026.
//

#include "tsa_network.h"

#include <iostream>
#include <string>
#include <curl/curl.h>

size_t writefunc(void *ptr, size_t size, size_t nmemb, void *userdata)
{ //adapted from https://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string/61805520#61805520
    auto *s = static_cast<std::string*>(userdata);
    s->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

CURLcode sendquery(CURLcode ret, char *buf, int len, std::string *s, const char *tsa_server, long &http_code) {
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/timestamp-query");
    if (ret != CURLE_OK) {
        std::cerr << "curl_global_init failed: "<< curl_easy_strerror(ret)<< '\n';
        curl_slist_free_all(headers);
        return ret;
    }

    if (CURL *curl = curl_easy_init()) {
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
        curl_easy_setopt(curl, CURLOPT_URL, tsa_server);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, len);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.2.1");
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);

        ret = curl_easy_perform(curl);

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
    }

    curl_slist_free_all(headers);
    return ret;
}
