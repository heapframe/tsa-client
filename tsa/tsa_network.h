//
// Created by axjp on 25/06/2026.
//

#ifndef TSA_CLIENT_TS_H
#define TSA_CLIENT_TS_H
#include <string>
#include <curl/curl.h>
#include <openssl/ts.h>

size_t writefunc(void *ptr, size_t size, size_t nmemb, void *userdata);

CURLcode sendquery(CURLcode ret, char *buf, int len, std::string *s, const char *tsa_server, long &http_code);

#endif //TSA_CLIENT_TS_H