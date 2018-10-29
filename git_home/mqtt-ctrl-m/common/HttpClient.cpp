/*
 * 本文件主要基于libcurl一些简单的http/https封装
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "HttpClient.h"

HttpRequest::HttpRequest(string& uri)
{
	curl = curl_easy_init();
	this->uri = uri;
	headers = NULL;
}

HttpRequest::~HttpRequest()
{
	if (curl)
	{
		curl_easy_cleanup(curl);
		curl = NULL;
	}
	if (headers)
	{
        curl_slist_free_all(headers);
	}
}

size_t HttpResponse::http_body_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	HttpResponse* http_resp = (HttpResponse*)userp;

	size_t len = 0;
    
    len = size * nmemb;
    
	http_resp->body.append((const char*)ptr, len);

    return len;
}

size_t HttpResponse::http_header_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	HttpResponse* http_resp = (HttpResponse*)userp;

	size_t len = 0;
    
    len = size * nmemb;
    
	http_resp->header.append((const char*)ptr, len);
	
#if 0
	string dump_str;
	dump_str.clear();
	dump_str.append((const char*)ptr, len);
	dump_str.replace("\r\n", "");
	dump_str.replace("\n", "");
	http_resp->header_list.push_back(dump_str);
	//cout << "header: " << dump_str << endl;
#endif
    return len;
}

void HttpRequest::AddHeader(string& key, string& value)
{
	string header = key + ": " + value;
    headers = curl_slist_append(headers, header.c_str());
    //curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
}

void HttpRequest::AddHeader(string& line)
{
    headers = curl_slist_append(headers, line.c_str());
    //curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
}

HttpResponse* HttpRequest::Post(string& data, int timeout, char* ca_path)
{
	HttpResponse* http_resp = new HttpResponse(curl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (ca_path)
    {
    	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true);
    	curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
    }
    else
    {
    	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    }
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); /* protect thread-safe */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_resp->http_body_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)http_resp);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, http_resp->http_header_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)http_resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    CURLcode res;
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
	{
		//cout << "---------------------error:out" << endl;
		delete(http_resp);
		http_resp = NULL;
	}
	return http_resp;
}

HttpResponse* HttpRequest::Get(int timeout, char* ca_path)
{
    //header = curl_slist_append(header, "Accept: application/json");
	HttpResponse* http_resp = new HttpResponse(curl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (ca_path)
    {
    	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true);
    	curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
    }
    else
    {
    	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    }
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);

	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); /* protect thread-safe */
    curl_easy_setopt(curl, CURLOPT_URL, uri.c_str()); 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_resp->http_body_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)http_resp);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, http_resp->http_header_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)http_resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res;
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
	{
		//cout << "--------------- error:out" << endl;
		delete(http_resp);
		http_resp = NULL;
	}
	return http_resp;
}

HttpResponse::HttpResponse(CURL* curl)
{
	body.clear();
	header.clear();
	//header_list.clear();
	this->curl = curl;
}

HttpResponse::~HttpResponse()
{

}

string& HttpResponse::GetBody()
{
	return body;
}

string& HttpResponse::GetHeader()
{
	return header;
}

#if 0
int HttpResponse::GetHeaderItem(string& item, string& value)
{
	int found = 0;
	list<string>::iterator it;
	for(it = header_list.begin(); it != header_list.end; it++)
	{
		string line = *it;
		size_t key_end = line.find(": ");
		if (key_end != string::npos)
		{
			string key(line, 0, key_end);
			if (key == item)
			{
				found = 1;
				value = line.substr(key_end + 2, line.length() - key_end - 2);
				break;
			}
		}
	}
	return found;
}
#endif

/* Maybe we need no init and exit */
void HttpClient_init()
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void HttpClient_exit()
{
    curl_global_cleanup();
}
