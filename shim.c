//
//  Shim.c
//  cURL
//
//  Created by Harry Wright on 12/02/2018.
//

#include <stdio.h>
#include "shim.h"

/* Error Handling */
CFErrorRef TCURLCodeToError(TCURLCode code) {
    CFStringRef errorDesc = CFStringCreateWithCString(NULL, curl_easy_strerror(code), kCFStringEncodingUTF8);
    CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(nil, 0, nil, nil);
    CFDictionarySetValue(dictionary, kCFErrorLocalizedDescriptionKey, errorDesc);

    return CFErrorCreate(NULL, kCURLWrapperErrorDomain(), code, dictionary);
}

CFErrorRef kCFErrorInvalidOption(TCURLOption option) {
    CFStringRef errorDesc = CFStringCreateWithCString(NULL, "Invalid Option", kCFStringEncodingUTF8);
    CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(nil, 0, nil, nil);
    CFDictionarySetValue(dictionary, kCFErrorLocalizedDescriptionKey, errorDesc);

    return CFErrorCreate(NULL, kCURLWrapperErrorDomain(), option, dictionary);
}

/* Initalisation */
Integer TCURLGlobalInit(TCURLGlobalOptions options) {
    return curl_global_init(options);
}

/* Setters */

#define ___curl_easy_set_opt(_c, _o, _v, _e) \
    if (_o == TCURLOptionPostData) { if (_e) { *_e = kCFErrorInvalidOption(TCURLOptionPostData); } return; }\
    TCURLEasyCode code = curl_easy_setopt(_c, _o, _v); \
    if (code != CURLE_OK && _e) { \
        *_e = curl_code_to_error(code); \
    }

void TCURLSetEasyOptionLong(TCURLEasyHandle handle, TCURLOption option, long value, CFErrorRef _Nullable *_Nullable error) {
  ___curl_easy_set_opt(handle, option, value, error)
}

void TCURLSetEasyOptionCString(TCURLEasyHandle handle, TCURLOption option, CString value, CFErrorRef _Nullable *_Nullable error) {
    ___curl_easy_set_opt(handle, option, value, error)
}

void TCURLSetEasyOptionInt64(TCURLEasyHandle handle, TCURLOption option, CInt64 value, CFErrorRef _Nullable *_Nullable error) {
    ___curl_easy_set_opt(handle, option, value, error)
}

void TCURLSetEasyOptionSList(TCURLEasyHandle handle, TCURLOption option, CSList value, CFErrorRef _Nullable *_Nullable error) {
    ___curl_easy_set_opt(handle, option, value, error)
}

void TCURLSetEasyOptionPointer(TCURLEasyHandle handle, TCURLOption option, AnyCPointer value, CFErrorRef _Nullable *_Nullable error) {
    ___curl_easy_set_opt(handle, option, value, error)
}

void TCURLSetEasyOptionBlock(TCURLEasyHandle handle, TCURLOption option, CURLFunctionBlock value, CFErrorRef _Nullable *_Nullable error) {
    ___curl_easy_set_opt(handle, option, value, error)
}

/* Getters */

#define ___curl_easy_get_info(_c, _i, _e, _v) \
    CURLcode code = curl_easy_getinfo(_c, _i, &_v); \
    if (code != CURLE_OK && _e) { \
    *_e = curl_code_to_error(code); \
    } \

CString TCURLEasyGetInfoCString(TCURLEasyHandle handle, TCURLInfo info, CFErrorRef _Nullable *_Nullable error) {
    CString value; ___curl_easy_get_info(handle, info, error, value); return value;
}

long TCURLEasyGetInfoLong(TCURLEasyHandle handle, TCURLInfo info, CFErrorRef _Nullable *_Nullable error) {
    long value; ___curl_easy_get_info(handle, info, error, value); return value;
}

CInt64 TCURLEasyGetInfoInt64(TCURLEasyHandle handle, TCURLInfo info, CFErrorRef _Nullable *_Nullable error) {
    CInt64 value; ___curl_easy_get_info(handle, info, error, value); return value;
}

CSList TCURLEasyGetInfoSList(TCURLEasyHandle handle, TCURLInfo info, CFErrorRef _Nullable *_Nullable error) {
    CSList value; __curl_easy_get_info(handle, info, error, value); return value;
}
