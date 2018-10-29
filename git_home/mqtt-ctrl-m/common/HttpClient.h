#ifndef _SRC_HTTPCLIENT_H_
#define _SRC_HTTPCLIENT_H_

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <openssl/ssl.h>

#include <list>

using namespace std;
using std::string;

class HttpResponse {
	CURL *curl;
	string body;
	string header;
	//list <string> header_list;
	//map<string, >

public:
	HttpResponse(CURL *curl);
	~HttpResponse();
	string& GetBody();
	string& GetHeader();
	//string& GetHeaderItem(string& item);
	static size_t http_body_cb(void *ptr, size_t size, size_t nmemb, void *userp);
	static size_t http_header_cb(void *ptr, size_t size, size_t nmemb, void *userp);
};

class HttpRequest {
	CURL *curl;
	string uri;
	struct curl_slist* headers;

public:
	HttpRequest(string& uri);
	~HttpRequest();

	/* Methods */
	void AddHeader(string& key, string& value);
	void AddHeader(string& line);
	HttpResponse* Post(string& data, int timeout = 15, char* ca_path = NULL);
	HttpResponse* Get(int timeout = 15, char* ca_path = NULL);
};


void HttpClient_init();
void HttpClient_exit();

#endif
