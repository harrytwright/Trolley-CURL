/****************************************************************************************
 *       _____  _    _  _____ ______  _____ __   __  _____  _   _ ______  _             *
 *      /  ___|| |  | ||_   _||  ___||_   _|\ \ / / /  __ \| | | || ___ \| |            *
 *      \ `--. | |  | |  | |  | |_     | |   \ V /  | /  \/| | | || |_/ /| |            *
 *       `--. \| |/\| |  | |  |  _|    | |    \ /   | |    | | | ||    / | |            *
 *      /\__/ /\  /\  / _| |_ | |      | |    | |   | \__/\| |_| || |\ \ | |____        *
 *      \____/  \/  \/  \___/ \_|      \_/    \_/    \____/ \___/ \_| \_|\_____/        *
 *                                                                                      *
 ****************************************************************************************/

#ifndef _shim_h_
#define _shim_h_

#include <curl/curl.h>

/** Use CoreFoundation to help wrap, will need to see if works with linux, if not work around?? */
#include <CoreFoundation/CoreFoundation.h>

#pragma mark - Typedef

typedef size_t (*curl_func)(void * ptr, size_t size, size_t num, void * ud);

typedef struct curl_slist * CSList;

typedef void * AnyVoid;

typedef long long CInt64;

typedef const char * CString;

#pragma mark - Error Handling

static CFErrorRef curl_code_to_error(CURLcode code) {
    CFStringRef errorDesc = CFStringCreateWithCString(NULL, curl_easy_strerror(code), kCFStringEncodingUTF8);
    CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(nil, 0, nil, nil);
    CFDictionarySetValue(dictionary, kCFErrorLocalizedDescriptionKey, errorDesc);

    return CFErrorCreate(NULL, CFSTR("trl.mbaas.curl.swift"), code, dictionary);
}

#pragma mark - Options

#define __TCOption_GET_MACRO(_1, _2, _3, NAME, ...) NAME
#define __TCOption_Anon(_name) TCURLOption##_name
#define __TCOption_C(_name, _type) TCURLOption##_name = _type
#define __TCOption_SWIFT_NAME(_name, _type, _swift) TCURLOption##_name CF_SWIFT_NAME(_swift) = _type

/** Set the new option with the old one */
#define TCOption(...) __TCOption_GET_MACRO(__VA_ARGS__, __TCOption_SWIFT_NAME, __TCOption_C, __TCOption_Anon, ) (__VA_ARGS__)

typedef long Integer;

/** Swift helper version of the CURLOPT */
typedef CF_ENUM(Integer, TCURLOption) {
  /* This is the FILE * or void * the regular output should be written to. */
  TCOption(WriteData, CURLOPT_WRITEDATA),

  /* The full URL to get/put */
  TCOption(URL, CURLOPT_URL, url),

  /* Port number to connect to, if other than default. */
  TCOption(Port, CURLOPT_PORT),

  /* Name of proxy to use. */
  TCOption(Proxy, CURLOPT_PROXY),

  /* "user:password;options" to use when fetching. */
  TCOption(UserAndPassword, CURLOPT_USERPWD),

  /* "user:password" to use with proxy. */
  TCOption(ProxyUserPassword, CURLOPT_PROXYUSERPWD),

  /* Range to get, specified as an ASCII string. */
  TCOption(Range, CURLOPT_RANGE),

  /* Specified file stream to upload from (use as input): */
  TCOption(ReadData, CURLOPT_READDATA),

  /* Buffer to receive error messages in, must be at least CURL_ERROR_SIZE
   * bytes big. If this is not used, error messages go to stderr instead: */
  TCOption(ErrorBuffer, CURLOPT_ERRORBUFFER),

  /* Function that will be called to store the output (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  TCOption(WriteFunction, CURLOPT_WRITEFUNCTION),

  /* Function that will be called to read the input (instead of fread). The
   * parameters will use fread() syntax, make sure to follow them. */
  TCOption(ReadFunction, CURLOPT_READFUNCTION),

  /* Time-out the read operation after this amount of seconds */
  TCOption(Timeout, CURLOPT_TIMEOUT),

  /* If the CURLOPT_INFILE is used, this can be used to inform libcurl about
   * how large the file being sent really is. That allows better error
   * checking and better verifies that the upload was successful. -1 means
   * unknown size.
   *
   * For large file support, there is also a _LARGE version of the key
   * which takes an off_t type, allowing platforms with larger off_t
   * sizes to handle larger files.  See below for INFILESIZE_LARGE.
   */
  TCOption(InfileSize, CURLOPT_INFILESIZE),

  /* POST static input fields. */
  TCOption(PostFields, CURLOPT_POSTFIELDS),

  /* Set the referrer page (needed by some CGIs) */
  TCOption(Referrer, CURLOPT_REFERER),

  /* Set the FTP PORT string (interface name, named or numerical IP address)
     Use i.e '-' to use default address. */
  TCOption(FTTPort, CURLOPT_FTPPORT),

  /* Set the User-Agent string (examined by some CGIs) */
  TCOption(UserAgent, CURLOPT_USERAGENT),

  /* If the download receives less than "low speed limit" bytes/second
   * during "low speed time" seconds, the operations is aborted.
   * You could i.e if you have a pretty high speed connection, abort if
   * it is less than 2000 bytes/sec during 20 seconds.
   */

  /* Set the "low speed limit" */
  TCOption(LowSpeedLimit, CURLOPT_LOW_SPEED_LIMIT),

  /* Set the "low speed time" */
  TCOption(LowSpeedLimitTime, CURLOPT_LOW_SPEED_TIME),

  /* Set the continuation offset.
   *
   * Note there is also a _LARGE version of this key which uses
   * off_t types, allowing for large file offsets on platforms which
   * use larger-than-32-bit off_t's.  Look below for RESUME_FROM_LARGE.
   */
  TCOption(ResumeFrom, CURLOPT_RESUME_FROM),

  /* Set cookie in request: */
  TCOption(Cookie, CURLOPT_COOKIE),

  /* This points to a linked list of headers, struct curl_slist kind. This
     list is also used for RTSP (in spite of its name) */
  TCOption(HTTPHeader, CURLOPT_HTTPHEADER),

  /* This points to a linked list of post entries, struct curl_httppost */
  TCOption(HTTPPost, CURLOPT_HTTPPOST),

  /* name of the file keeping your private SSL-certificate */
  TCOption(SSLCert, CURLOPT_SSLCERT),

  /* password for the SSL or SSH private key */
  TCOption(KeyPassword, CURLOPT_KEYPASSWD),

  /* send TYPE parameter? */
  TCOption(CLRF, CURLOPT_CRLF),

  /* send linked-list of QUOTE commands */
  TCOption(Quote, CURLOPT_QUOTE),

  /* send FILE * or void * to store headers to, if you use a callback it
     is simply passed to the callback unmodified */
  TCOption(HeaderData, CURLOPT_HEADERDATA),

  /* point to a file to read the initial cookies from, also enables
     "cookie awareness" */
  TCOption(CookieFile, CURLOPT_COOKIEFILE),

  /* What version to specifically try to use.
     See CURL_SSLVERSION defines below. */
  TCOption(SSLVersion, CURLOPT_SSLVERSION),

  /* What kind of HTTP time condition to use, see defines */
  TCOption(TimeCondition, CURLOPT_TIMECONDITION),

  /* Time to use with the above condition. Specified in number of seconds
     since 1 Jan 1970 */
  TCOption(TimeValue, CURLOPT_TIMEVALUE),

  /* 35 = OBSOLETE */

  /* Custom request, for customizing the get command like
     HTTP: DELETE, TRACE and others
     FTP: to use a different list command
     */
  TCOption(CustomRequest, CURLOPT_CUSTOMREQUEST),

  /* FILE handle to use instead of stderr */
  TCOption(Stderr, CURLOPT_STDERR),

  /* 38 is not used */

  /* send linked-list of post-transfer QUOTE commands */
  TCOption(PostQuote, CURLOPT_POSTQUOTE),

  TCOption(Verbose, CURLOPT_VERBOSE),      /* talk a lot */
  TCOption(Header, CURLOPT_HEADER),       /* throw the header out too */
  TCOption(NoProgress, CURLOPT_NOPROGRESS),   /* shut off the progress meter */
  TCOption(Nobody, CURLOPT_NOBODY),       /* use HEAD to get http document */
  TCOption(FailOnError, CURLOPT_FAILONERROR),  /* no output on http error codes >= 400 */
  TCOption(Upload, CURLOPT_UPLOAD),       /* this is an upload */
  TCOption(Post, CURLOPT_POST),         /* HTTP POST method */
  TCOption(DirListOnly, CURLOPT_DIRLISTONLY),  /* bare names when listing directories */

  TCOption(Append, CURLOPT_APPEND),       /* Append instead of overwrite on upload! */

  /* Specify whether to read the user+password from the .netrc or the URL.
   * This must be one of the CURL_NETRC_* enums below. */
  TCOption(Netrc, CURLOPT_NETRC),

  TCOption(FollowLocation, CURLOPT_FOLLOWLOCATION),  /* use Location: Luke! */

  TCOption(TransferText, CURLOPT_TRANSFERTEXT), /* transfer data in text/ASCII format */
  TCOption(Put, CURLOPT_PUT),          /* HTTP PUT */

  /* 55 = OBSOLETE */

  /* DEPRECATED
   * Function that will be called instead of the internal progress display
   * function. This function should be defined as the curl_progress_callback
   * prototype defines. */
  TCOption(ProgressFunction, CURLOPT_PROGRESSFUNCTION),

  /* Data passed to the CURLOPT_PROGRESSFUNCTION and CURLOPT_XFERINFOFUNCTION
     callbacks */
  TCOption(ProgressData, CURLOPT_PROGRESSDATA),

  /* We want the referrer field set automatically when following locations */
  TCOption(AutoReferer, CURLOPT_AUTOREFERER),

  /* Port of the proxy, can be set in the proxy string as well with:
     "[host]:[port]" */
  TCOption(ProxyPort, CURLOPT_PROXYPORT),

  /* size of the POST input data, if strlen() is not good to use */
  TCOption(PostfieldSize, CURLOPT_POSTFIELDSIZE),

  /* tunnel non-http operations through a HTTP proxy */
  TCOption(HTTPProxyTunnel, CURLOPT_HTTPPROXYTUNNEL),

  /* Set the interface string to use as outgoing network interface */
  TCOption(Interface, CURLOPT_INTERFACE),

  /* Set the krb4/5 security level, this also enables krb4/5 awareness.  This
   * is a string, 'clear', 'safe', 'confidential' or 'private'.  If the string
   * is set but doesn't match one of these, 'private' will be used.  */
  TCOption(KrbLevel, CURLOPT_KRBLEVEL),

  /* Set if we should verify the peer in ssl handshake, set 1 to verify. */
  TCOption(SSLVerifyPeer, CURLOPT_SSL_VERIFYPEER),

  /* The CApath or CAfile used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  TCOption(CAInfo, CURLOPT_CAINFO),

  /* Maximum number of http redirects to follow */
  TCOption(MaxRedirs, CURLOPT_MAXREDIRS),

  /* Pass a long set to 1 to get the date of the requested document (if
     possible)! Pass a zero to shut it off. */
  TCOption(FileTime, CURLOPT_FILETIME),

  /* This points to a linked list of telnet options */
  TCOption(TelnetOptions, CURLOPT_TELNETOPTIONS),

  /* Max amount of cached alive connections */
  TCOption(MaxConnects, CURLOPT_MAXCONNECTS),

  /* Set to explicitly use a new connection for the upcoming transfer.
     Do not use this unless you're absolutely sure of this, as it makes the
     operation slower and is less friendly for the network. */
  TCOption(FreshConnect, CURLOPT_FRESH_CONNECT),

  /* Set to explicitly forbid the upcoming transfer's connection to be re-used
     when done. Do not use this unless you're absolutely sure of this, as it
     makes the operation slower and is less friendly for the network. */
  TCOption(ForbidReuse, CURLOPT_FORBID_REUSE),

  /* Set to a file name that contains random data for libcurl to use to
     seed the random engine when doing SSL connects. */
  TCOption(RandomFile, CURLOPT_RANDOM_FILE),

  /* Set to the Entropy Gathering Daemon socket pathname */
  TCOption(EGDSocket, CURLOPT_EGDSOCKET),

  /* Time-out connect operations after this amount of seconds, if connects are
     OK within this time, then fine... This only aborts the connect phase. */
  TCOption(ConnectTimeout, CURLOPT_CONNECTTIMEOUT),

  /* Function that will be called to store headers (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  TCOption(HeaderFunction, CURLOPT_HEADERFUNCTION),

  /* Set this to force the HTTP request to get back to GET. Only really usable
     if POST, PUT or a custom request have been used first.
   */
  TCOption(HTTPGet, CURLOPT_HTTPGET),

  /* Set if we should verify the Common name from the peer certificate in ssl
   * handshake, set 1 to check existence, 2 to ensure that it matches the
   * provided hostname. */
  TCOption(SSLVerifyHost, CURLOPT_SSL_VERIFYHOST) ,

  /* Specify which file name to write all known cookies in after completed
     operation. Set file name to "-" (dash) to make it go to stdout. */
  TCOption(CookieJar, CURLOPT_COOKIEJAR),

  /* Specify which SSL ciphers to use */
  TCOption(SSLCipherList, CURLOPT_SSL_CIPHER_LIST),

  /* Specify which HTTP version to use! This must be set to one of the
     CURL_HTTP_VERSION* enums set below. */
  TCOption(HTTPVersion, CURLOPT_HTTP_VERSION),

  /* Specifically switch on or off the FTP engine's use of the EPSV command. By
     default, that one will always be attempted before the more traditional
     PASV command. */
  TCOption(FTPUseEPSV, CURLOPT_FTP_USE_EPSV),

  /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") */
  TCOption(SSLCertType, CURLOPT_SSLCERTTYPE),

  /* name of the file keeping your private SSL-key */
  TCOption(SSLKey, CURLOPT_SSLKEY),

  /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") */
  TCOption(SSLKeyType, CURLOPT_SSLKEYTYPE),

  /* crypto engine for the SSL-sub system */
  TCOption(SSLEngine, CURLOPT_SSLENGINE),

  /* set the crypto engine for the SSL-sub system as default
     the param has no meaning...
   */
  TCOption(SSLEngineDefault, CURLOPT_SSLENGINE_DEFAULT),

  /* Non-zero value means to use the global dns cache */
  TCOption(DNSUseGlobalCache, CURLOPT_DNS_USE_GLOBAL_CACHE), /* DEPRECATED, do not use! */

  /* DNS cache timeout */
  TCOption(DNSCacheTimeout, CURLOPT_DNS_CACHE_TIMEOUT),

  /* send linked-list of pre-transfer QUOTE commands */
  TCOption(PreQuote, CURLOPT_PREQUOTE),

  /* set the debug function */
  TCOption(DebugFunction, CURLOPT_DEBUGFUNCTION),

  /* set the data for the debug function */
  TCOption(DebugData, CURLOPT_DEBUGDATA),

  /* mark this as start of a cookie session */
  TCOption(CookieSession, CURLOPT_COOKIESESSION),

  /* The CApath directory used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  TCOption(CAPath, CURLOPT_CAPATH),

  /* Instruct libcurl to use a smaller receive buffer */
  TCOption(BufferSize, CURLOPT_BUFFERSIZE),

  /* Instruct libcurl to not use any signal/alarm handlers, even when using
     timeouts. This option is useful for multi-threaded applications.
     See libcurl-the-guide for more background information. */
  TCOption(NoSignal, CURLOPT_NOSIGNAL),

  /* Provide a CURLShare for mutexing non-ts data */
  TCOption(Share, CURLOPT_SHARE),

  /* indicates type of proxy. accepted values are CURLPROXY_HTTP (default),
     CURLPROXY_HTTPS, CURLPROXY_SOCKS4, CURLPROXY_SOCKS4A and
     CURLPROXY_SOCKS5. */
  TCOption(ProxyType, CURLOPT_PROXYTYPE),

  /* Set the Accept-Encoding string. Use this to tell a server you would like
     the response to be compressed. Before 7.21.6, this was known as
     CURLOPT_ENCODING */
  TCOption(AcceptEncoding, CURLOPT_ACCEPT_ENCODING),

  /* Set pointer to private data */
  TCOption(Private, CURLOPT_PRIVATE),

  /* Set aliases for HTTP 200 in the HTTP Response header */
  TCOption(HTTP200Aliases, CURLOPT_HTTP200ALIASES),

  /* Continue to send authentication (user+password) when following locations,
     even when hostname changed. This can potentially send off the name
     and password to whatever host the server decides. */
  TCOption(UnrestrictedAuth, CURLOPT_UNRESTRICTED_AUTH),

  /* Specifically switch on or off the FTP engine's use of the EPRT command (
     it also disables the LPRT attempt). By default, those ones will always be
     attempted before the good old traditional PORT command. */
  TCOption(FTPUseEPRT, CURLOPT_FTP_USE_EPRT),

  /* Set this to a bitmask value to enable the particular authentications
     methods you like. Use this in combination with CURLOPT_USERPWD.
     Note that setting multiple bits may cause extra network round-trips. */
  TCOption(HTTPAuth, CURLOPT_HTTPAUTH),

  /* Set the ssl context callback function, currently only for OpenSSL ssl_ctx
     in second argument. The function must be matching the
     curl_ssl_ctx_callback proto. */
  TCOption(SSLCtxFunction, CURLOPT_SSL_CTX_FUNCTION),

  /* Set the userdata for the ssl context callback function's third
     argument */
  TCOption(SSLCtxData, CURLOPT_SSL_CTX_DATA),

  /* FTP Option that causes missing dirs to be created on the remote server.
     In 7.19.4 we introduced the convenience enums for this option using the
     CURLFTP_CREATE_DIR prefix.
  */
  TCOption(FTPCreateMissingDirs, CURLOPT_FTP_CREATE_MISSING_DIRS),

  /* Set this to a bitmask value to enable the particular authentications
     methods you like. Use this in combination with CURLOPT_PROXYUSERPWD.
     Note that setting multiple bits may cause extra network round-trips. */
  TCOption(ProxyAuth, CURLOPT_PROXYAUTH),

  /* FTP option that changes the timeout, in seconds, associated with
     getting a response.  This is different from transfer timeout time and
     essentially places a demand on the FTP server to acknowledge commands
     in a timely manner. */
  TCOption(FTPResponseTimeout, CURLOPT_FTP_RESPONSE_TIMEOUT),

  /* Set this option to one of the CURL_IPRESOLVE_* defines (see below) to
     tell libcurl to resolve names to those IP versions only. This only has
     affect on systems with support for more than one, i.e IPv4 _and_ IPv6. */
  TCOption(IPResolve, CURLOPT_IPRESOLVE),

  /* Set this option to limit the size of a file that will be downloaded from
     an HTTP or FTP server.

     Note there is also _LARGE version which adds large file support for
     platforms which have larger off_t sizes.  See MAXFILESIZE_LARGE below. */
  TCOption(MaxFilesize, CURLOPT_MAXFILESIZE),

  /* See the comment for INFILESIZE above, but in short, specifies
   * the size of the file being uploaded.  -1 means unknown.
   */
  TCOption(InFilesizeLarge, CURLOPT_INFILESIZE_LARGE),

  /* Sets the continuation offset.  There is also a LONG version of this;
   * look above for RESUME_FROM.
   */
  TCOption(ResumeFromLarge, CURLOPT_RESUME_FROM_LARGE),

  /* Sets the maximum size of data that will be downloaded from
   * an HTTP or FTP server.  See MAXFILESIZE above for the LONG version.
   */
  TCOption(MaxFilesizeLarge, CURLOPT_MAXFILESIZE_LARGE),

  /* Set this option to the file name of your .netrc file you want libcurl
     to parse (using the CURLOPT_NETRC option). If not set, libcurl will do
     a poor attempt to find the user's home directory and check for a .netrc
     file in there. */
  TCOption(NetrcFile, CURLOPT_NETRC_FILE),

  /* Enable SSL/TLS for FTP, pick one of:
     CURLUSESSL_TRY     - try using SSL, proceed anyway otherwise
     CURLUSESSL_CONTROL - SSL for the control connection or fail
     CURLUSESSL_ALL     - SSL for all communication or fail
  */
  TCOption(UseSSL, CURLOPT_USE_SSL),

  /* The _LARGE version of the standard POSTFIELDSIZE option */
  TCOption(PostFieldsizeLarge, CURLOPT_POSTFIELDSIZE_LARGE),

  /* Enable/disable the TCP Nagle algorithm */
  TCOption(TCpPNodelay, CURLOPT_TCP_NODELAY),

  /* When FTP over SSL/TLS is selected (with CURLOPT_USE_SSL), this option
     can be used to change libcurl's default action which is to first try
     "AUTH SSL" and then "AUTH TLS" in this order, and proceed when a OK
     response has been received.

     Available parameters are:
     CURLFTPAUTH_DEFAULT - let libcurl decide
     CURLFTPAUTH_SSL     - try "AUTH SSL" first, then TLS
     CURLFTPAUTH_TLS     - try "AUTH TLS" first, then SSL
  */
  TCOption(FTPSSLAuth, CURLOPT_FTPSSLAUTH),

  TCOption(IoctlFunction, CURLOPT_IOCTLFUNCTION),
  TCOption(IoctlData, CURLOPT_IOCTLDATA),

  /* zero terminated string for pass on to the FTP server when asked for
     "account" info */
  TCOption(FTPAccount, CURLOPT_FTP_ACCOUNT),

  /* feed cookie into cookie engine */
  TCOption(CookieList, CURLOPT_COOKIELIST),

  /* ignore Content-Length */
  TCOption(IgnoreContentLength, CURLOPT_IGNORE_CONTENT_LENGTH),

  /* Set to non-zero to skip the IP address received in a 227 PASV FTP server
     response. Typically used for FTP-SSL purposes but is not restricted to
     that. libcurl will then instead use the same IP address it used for the
     control connection. */
  TCOption(FTPSkipPasvIP, CURLOPT_FTP_SKIP_PASV_IP),

  /* Select "file method" to use when doing FTP, see the curl_ftpmethod
     above. */
  TCOption(FTPFileMethod, CURLOPT_FTP_FILEMETHOD),

  /* Local port number to bind the socket to */
  TCOption(LocalPort, CURLOPT_LOCALPORT),

  /* Number of ports to try, including the first one set with LOCALPORT.
     Thus, setting it to 1 will make no additional attempts but the first.
  */
  TCOption(LocalPortRange, CURLOPT_LOCALPORTRANGE),

  /* no transfer, set up connection and let application use the socket by
     extracting it with CURLINFO_LASTSOCKET */
  TCOption(ConnectOnly, CURLOPT_CONNECT_ONLY),

  /* Function that will be called to convert from the
     network encoding (instead of using the iconv calls in libcurl) */
  TCOption(ConvFromNetworkFunction, CURLOPT_CONV_FROM_NETWORK_FUNCTION),

  /* Function that will be called to convert to the
     network encoding (instead of using the iconv calls in libcurl) */
  TCOption(ConvToNetworkFunction, CURLOPT_CONV_TO_NETWORK_FUNCTION),

  /* Function that will be called to convert from UTF8
     (instead of using the iconv calls in libcurl)
     Note that this is used only for SSL certificate processing */
  TCOption(ConvFromUtf8Function, CURLOPT_CONV_FROM_UTF8_FUNCTION),

  /* if the connection proceeds too quickly then need to slow it down */
  /* limit-rate: maximum number of bytes per second to send or receive */
  TCOption(MaxSendSpeedLarge, CURLOPT_MAX_SEND_SPEED_LARGE),
  TCOption(MaxRecvSpeedLarge, CURLOPT_MAX_RECV_SPEED_LARGE),

  /* Pointer to command string to send if USER/PASS fails. */
  TCOption(FTPAlternativeToUser, CURLOPT_FTP_ALTERNATIVE_TO_USER),

  /* callback function for setting socket options */
  TCOption(SockOptFunction, CURLOPT_SOCKOPTFUNCTION),
  TCOption(SockOptData, CURLOPT_SOCKOPTDATA),

  /* set to 0 to disable session ID re-use for this transfer, default is
     enabled (== 1) */
  TCOption(SSLSessionidCache, CURLOPT_SSL_SESSIONID_CACHE),

  /* allowed SSH authentication methods */
  TCOption(SSHAuthTypes, CURLOPT_SSH_AUTH_TYPES),

  /* Used by scp/sftp to do public/private key authentication */
  TCOption(SSHPublicKeyfile, CURLOPT_SSH_PUBLIC_KEYFILE),
  TCOption(SSHPrivateKeyfile, CURLOPT_SSH_PRIVATE_KEYFILE),

  /* Send CCC (Clear Command Channel) after authentication */
  TCOption(FTPSSLCcc, CURLOPT_FTP_SSL_CCC, ftpSSLClearCommandChannel),

  /* Same as TIMEOUT and CONNECTTIMEOUT, but with ms resolution */
  TCOption(TimeoutMs, CURLOPT_TIMEOUT_MS),
  TCOption(ConnectTimeoutMs, CURLOPT_CONNECTTIMEOUT_MS),

  /* set to zero to disable the libcurl's decoding and thus pass the raw body
     data to the application even when it is encoded/compressed */
  TCOption(HTTPTransferDecoding, CURLOPT_HTTP_TRANSFER_DECODING),
  TCOption(HTTPContentDecoding, CURLOPT_HTTP_CONTENT_DECODING),

  /* Permission used when creating new files and directories on the remote
     server for protocols that support it, SFTP/SCP/FILE */
  TCOption(NewFilePerms, CURLOPT_NEW_FILE_PERMS),
  TCOption(NewDirectoryPerms, CURLOPT_NEW_DIRECTORY_PERMS),

  /* Set the behaviour of POST when redirecting. Values must be set to one
     of CURL_REDIR* defines below. This used to be called CURLOPT_POST301 */
  TCOption(PostRedir, CURLOPT_POSTREDIR),

  /* used by scp/sftp to verify the host's public key */
  TCOption(SSHHostPublicKeyMd5, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5),

  /* Callback function for opening socket (instead of socket(2)). Optionally,
     callback is able change the address or refuse to connect returning
     CURL_SOCKET_BAD.  The callback should have type
     curl_opensocket_callback */
  TCOption(OpenSocketFunction, CURLOPT_OPENSOCKETFUNCTION),
  TCOption(OpenSocketData, CURLOPT_OPENSOCKETDATA),

  /* POST volatile input fields. */
  TCOption(CopyPostFields, CURLOPT_COPYPOSTFIELDS),

  /* set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy */
  TCOption(ProxyTransferMode, CURLOPT_PROXY_TRANSFER_MODE),

  /* Callback function for seeking in the input stream */
  TCOption(SeekFunction, CURLOPT_SEEKFUNCTION),
  TCOption(SeekData, CURLOPT_SEEKDATA),

  /* CRL file */
  TCOption(CrlFile, CURLOPT_CRLFILE),

  /* Issuer certificate */
  TCOption(IssuerCert, CURLOPT_ISSUERCERT, IssuerCertificate),

  /* (IPv6) Address scope */
  TCOption(AddressScope, CURLOPT_ADDRESS_SCOPE),

  /* Collect certificate chain info and allow it to get retrievable with
     CURLINFO_CERTINFO after the transfer is complete. */
  TCOption(CertInfo, CURLOPT_CERTINFO),

  /* "name" and "pwd" to use when fetching. */
  TCOption(Username, CURLOPT_USERNAME),
  TCOption(Password, CURLOPT_PASSWORD),

    /* "name" and "pwd" to use with Proxy when fetching. */
  TCOption(ProxyUsername, CURLOPT_PROXYUSERNAME),
  TCOption(ProxyPassword, CURLOPT_PROXYPASSWORD),

  /* Comma separated list of hostnames defining no-proxy zones. These should
     match both hostnames directly, and hostnames within a domain. For
     example, local.com will match local.com and www.local.com, but NOT
     notlocal.com or www.notlocal.com. For compatibility with other
     implementations of this, .local.com will be considered to be the same as
     local.com. A single * is the only valid wildcard, and effectively
     disables the use of proxy. */
  TCOption(NoProxy, CURLOPT_NOPROXY),

  /* block size for TFTP transfers */
  TCOption(TFTPBlockSize, CURLOPT_TFTP_BLKSIZE),

  /* Socks Service */
  TCOption(Socks5GssapiNec, CURLOPT_SOCKS5_GSSAPI_NEC),

  /* set the bitmask for the protocols that are allowed to be used for the
     transfer, which thus helps the app which takes URLs from users or other
     external inputs and want to restrict what protocol(s) to deal
     with. Defaults to CURLPROTO_ALL. */
  TCOption(Protocols, CURLOPT_PROTOCOLS),

  /* set the bitmask for the protocols that libcurl is allowed to follow to,
     as a subset of the CURLOPT_PROTOCOLS ones. That means the protocol needs
     to be set in both bitmasks to be allowed to get redirected to. Defaults
     to all protocols except FILE and SCP. */
  TCOption(RedirProtocols, CURLOPT_REDIR_PROTOCOLS),

  /* set the SSH knownhost file name to use */
  TCOption(SSHKnownhosts, CURLOPT_SSH_KNOWNHOSTS),

  /* set the SSH host key callback, must point to a curl_sshkeycallback
     function */
  TCOption(SSHKeyfunction, CURLOPT_SSH_KEYFUNCTION),

  /* set the SSH host key callback custom pointer */
  TCOption(SSHKeydata, CURLOPT_SSH_KEYDATA),

  /* set the SMTP mail originator */
  TCOption(MailFrom, CURLOPT_MAIL_FROM),

  /* set the list of SMTP mail receiver(s) */
  TCOption(MailRcpt, CURLOPT_MAIL_RCPT),

  /* FTP: send PRET before PASV */
  TCOption(FTPUsePret, CURLOPT_FTP_USE_PRET),

  /* RTSP request method (OPTIONS, SETUP, PLAY, etc...) */
  TCOption(RtspRequest, CURLOPT_RTSP_REQUEST),

  /* The RTSP session identifier */
  TCOption(RtspSessionId, CURLOPT_RTSP_SESSION_ID),

  /* The RTSP stream URI */
  TCOption(RtspStreamURI, CURLOPT_RTSP_STREAM_URI, rtspStreamURI),

  /* The Transport: header to use in RTSP requests */
  TCOption(RtspTransport, CURLOPT_RTSP_TRANSPORT),

  /* Manually initialize the client RTSP CSeq for this handle */
  TCOption(RtspClientCseq, CURLOPT_RTSP_CLIENT_CSEQ),

  /* Manually initialize the server RTSP CSeq for this handle */
  TCOption(RtspServerCseq, CURLOPT_RTSP_SERVER_CSEQ),

  /* The stream to pass to INTERLEAVEFUNCTION. */
  TCOption(InterLeaveData, CURLOPT_INTERLEAVEDATA),

  /* Let the application define a custom write method for RTP data */
  TCOption(InterLeaveFunction, CURLOPT_INTERLEAVEFUNCTION),

  /* Turn on wildcard matching */
  TCOption(WildcardMatch, CURLOPT_WILDCARDMATCH),

  /* Directory matching callback called before downloading of an
     individual file (chunk) started */
  TCOption(ChunkBgnFunction, CURLOPT_CHUNK_BGN_FUNCTION, chunkBeginFunction),

  /* Directory matching callback called after the file (chunk)
     was downloaded, or skipped */
  TCOption(ChunkEndFunction, CURLOPT_CHUNK_END_FUNCTION),

  /* Change match (fnmatch-like) callback for wildcard matching */
  TCOption(FnmatchFunction, CURLOPT_FNMATCH_FUNCTION),

  /* Let the application define custom chunk data pointer */
  TCOption(ChunkData, CURLOPT_CHUNK_DATA),

  /* FNMATCH_FUNCTION user pointer */
  TCOption(FnmatchData, CURLOPT_FNMATCH_DATA),

  /* send linked-list of name:port:address sets */
  TCOption(Resolve, CURLOPT_RESOLVE),

  /* Set a username for authenticated TLS */
  TCOption(TLSAuthUsername, CURLOPT_TLSAUTH_USERNAME),

  /* Set a password for authenticated TLS */
  TCOption(TLSAuthPassword, CURLOPT_TLSAUTH_PASSWORD),

  /* Set authentication type for authenticated TLS */
  TCOption(TLSAuthType, CURLOPT_TLSAUTH_TYPE),

  /* Set to 1 to enable the "TE:" header in HTTP requests to ask for
     compressed transfer-encoded responses. Set to 0 to disable the use of TE:
     in outgoing requests. The current default is 0, but it might change in a
     future libcurl release.

     libcurl will ask for the compressed methods it knows of, and if that
     isn't any, it will not ask for transfer-encoding at all even if this
     option is set to 1.

  */
  TCOption(TransferEncoding, CURLOPT_TRANSFER_ENCODING),

  /* Callback function for closing socket (instead of close(2)). The callback
     should have type curl_closesocket_callback */
  TCOption(CloseSocketFunction, CURLOPT_CLOSESOCKETFUNCTION),
  TCOption(CloseSocketData, CURLOPT_CLOSESOCKETDATA),

  /* allow GSSAPI credential delegation */
  TCOption(GssapiDelegation, CURLOPT_GSSAPI_DELEGATION),

  /* Set the name servers to use for DNS resolution */
  TCOption(DnsServers, CURLOPT_DNS_SERVERS),

  /* Time-out accept operations (currently for FTP only) after this amount
     of milliseconds. */
  TCOption(AcceptTimeoutMs, CURLOPT_ACCEPTTIMEOUT_MS),

  /* Set TCP keepalive */
  TCOption(TCPKeepAlive, CURLOPT_TCP_KEEPALIVE),

  /* non-universal keepalive knobs (Linux, AIX, HP-UX, more) */
  TCOption(TCPKeepIdle, CURLOPT_TCP_KEEPIDLE) ,
  TCOption(TCPKeepIntvl, CURLOPT_TCP_KEEPINTVL),

  /* Enable/disable specific SSL features with a bitmask, see CURLSSLOPT_* */
  TCOption(SSLOptions, CURLOPT_SSL_OPTIONS),

  /* Set the SMTP auth originator */
  TCOption(MailAuth, CURLOPT_MAIL_AUTH),

  /* Enable/disable SASL initial response */
  TCOption(SASLInternalResponse, CURLOPT_SASL_IR),

  /* Function that will be called instead of the internal progress display
   * function. This function should be defined as the curl_xferinfo_callback
   * prototype defines. (Deprecates CURLOPT_PROGRESSFUNCTION) */
  TCOption(Xferinfofunction, CURLOPT_XFERINFOFUNCTION),

  /* The XOAUTH2 bearer token */
  TCOption(XOAuth2Bearer, CURLOPT_XOAUTH2_BEARER),

  /* Set the interface string to use as outgoing network
   * interface for DNS requests.
   * Only supported by the c-ares DNS backend */
  TCOption(DNSInterface, CURLOPT_DNS_INTERFACE),

  /* Set the local IPv4 address to use for outgoing DNS requests.
   * Only supported by the c-ares DNS backend */
  TCOption(DnsLocalIP4, CURLOPT_DNS_LOCAL_IP4),

  /* Set the local IPv4 address to use for outgoing DNS requests.
   * Only supported by the c-ares DNS backend */
  TCOption(DnsLocalIP6, CURLOPT_DNS_LOCAL_IP6),

  /* Set authentication options directly */
  TCOption(LoginOptions, CURLOPT_LOGIN_OPTIONS),

  /* Enable/disable TLS NPN extension (http2 over ssl might fail without) */
  TCOption(SSLEnableNpn, CURLOPT_SSL_ENABLE_NPN),

  /* Enable/disable TLS ALPN extension (http2 over ssl might fail without) */
  TCOption(SSLEnableAlpn, CURLOPT_SSL_ENABLE_ALPN),

  /* Time to wait for a response to a HTTP request containing an
   * Expect: 100-continue header before sending the data anyway. */
  TCOption(Expect100TimeoutMs, CURLOPT_EXPECT_100_TIMEOUT_MS),

  /* This points to a linked list of headers used for proxy requests only,
     struct curl_slist kind */
  TCOption(ProxyHeader, CURLOPT_PROXYHEADER),

  /* Pass in a bitmask of "header options" */
  TCOption(HeaderOpt, CURLOPT_HEADEROPT),

  /* The public key in DER form used to validate the peer public key
     this option is used only if SSL_VERIFYPEER is true */
  TCOption(PinnedPublicKey, CURLOPT_PINNEDPUBLICKEY),

  /* Path to Unix domain socket */
  TCOption(UnixSocketPath, CURLOPT_UNIX_SOCKET_PATH),

  /* Set if we should verify the certificate status. */
  TCOption(SSLVerifyStatus, CURLOPT_SSL_VERIFYSTATUS),

  /* Set if we should enable TLS false start. */
  TCOption(SSLFalseStart, CURLOPT_SSL_FALSESTART),

  /* Do not squash dot-dot sequences */
  TCOption(PathAsIs, CURLOPT_PATH_AS_IS),

  /* Proxy Service Name */
  TCOption(ProxyServiceName, CURLOPT_PROXY_SERVICE_NAME),

  /* Service Name */
  TCOption(ServiceName, CURLOPT_SERVICE_NAME),

  /* Wait/don't wait for pipe/mutex to clarify */
  TCOption(PipeWait, CURLOPT_PIPEWAIT),

  /* Set the protocol used when curl is given a URL without a protocol */
  TCOption(DefaultProtocol, CURLOPT_DEFAULT_PROTOCOL),

  /* Set stream weight, 1 - 256 (default is 16) */
  TCOption(StreamWeight, CURLOPT_STREAM_WEIGHT),

  /* Set stream dependency on another CURL handle */
  TCOption(StreamDepends, CURLOPT_STREAM_DEPENDS),

  /* Set E-xclusive stream dependency on another CURL handle */
  TCOption(StreamDependsE, CURLOPT_STREAM_DEPENDS_E),

  /* Do not send any tftp option requests to the server */
  TCOption(TFPTNoOptions, CURLOPT_TFTP_NO_OPTIONS),

  /* Linked-list of host:port:connect-to-host:connect-to-port,
     overrides the URL's host:port (only for the network layer) */
  TCOption(ConnectTo, CURLOPT_CONNECT_TO),

  /* Set TCP Fast Open */
  TCOption(TCPFastOpen, CURLOPT_TCP_FASTOPEN),

  /* Continue to send data if the server responds early with an
   * HTTP status code >= 300 */
  TCOption(KeepSendingOnError, CURLOPT_KEEP_SENDING_ON_ERROR),

  /* The CApath or CAfile used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  TCOption(ProxyCAInfo, CURLOPT_PROXY_CAINFO),

  /* The CApath directory used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  TCOption(ProxyCAPath, CURLOPT_PROXY_CAPATH),

  /* Set if we should verify the proxy in ssl handshake,
     set 1 to verify. */
  TCOption(ProxySSLVerifyPeer, CURLOPT_PROXY_SSL_VERIFYPEER),

  /* Set if we should verify the Common name from the proxy certificate in ssl
   * handshake, set 1 to check existence, 2 to ensure that it matches
   * the provided hostname. */
  TCOption(ProxySSLVerifyHost, CURLOPT_PROXY_SSL_VERIFYHOST),

  /* What version to specifically try to use for proxy.
     See CURL_SSLVERSION defines below. */
  TCOption(ProxySSLVersion, CURLOPT_PROXY_SSLVERSION),

  /* Set a username for authenticated TLS for proxy */
  TCOption(ProxyTLSAuthUsername, CURLOPT_PROXY_TLSAUTH_USERNAME),

  /* Set a password for authenticated TLS for proxy */
  TCOption(ProxyTLSAuthPassword, CURLOPT_PROXY_TLSAUTH_PASSWORD),

  /* Set authentication type for authenticated TLS for proxy */
  TCOption(ProxyTLSAuthType, CURLOPT_PROXY_TLSAUTH_TYPE),

  /* name of the file keeping your private SSL-certificate for proxy */
  TCOption(ProxySSLCert, CURLOPT_PROXY_SSLCERT),

  /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") for
     proxy */
  TCOption(ProxySSLCerttype, CURLOPT_PROXY_SSLCERTTYPE),

  /* name of the file keeping your private SSL-key for proxy */
  TCOption(ProxySSLKey, CURLOPT_PROXY_SSLKEY),

  /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") for
     proxy */
  TCOption(ProxySSLKeyType, CURLOPT_PROXY_SSLKEYTYPE),

  /* password for the SSL private key for proxy */
  TCOption(ProxyKeyPassword, CURLOPT_PROXY_KEYPASSWD),

  /* Specify which SSL ciphers to use for proxy */
  TCOption(ProxySSLCipherList, CURLOPT_PROXY_SSL_CIPHER_LIST),

  /* CRL file for proxy */
  TCOption(ProxyCRLFile, CURLOPT_PROXY_CRLFILE),

  /* Enable/disable specific SSL features with a bitmask for proxy, see
     CURLSSLOPT_* */
  TCOption(ProxySSLOptions, CURLOPT_PROXY_SSL_OPTIONS),

  /* Name of pre proxy to use. */
  TCOption(PreProxy, CURLOPT_PRE_PROXY),

  /* The public key in DER form used to validate the proxy public key
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  TCOption(ProxyPinnedPublicKey, CURLOPT_PROXY_PINNEDPUBLICKEY),

  /* Path to an abstract Unix domain socket */
  TCOption(AbstractUnixSocket, CURLOPT_ABSTRACT_UNIX_SOCKET),

  /* Suppress proxy CONNECT response headers from user callbacks */
  TCOption(SuppressConnectHeaders, CURLOPT_SUPPRESS_CONNECT_HEADERS),

    /* Custom option, sending this will set `CURLOPT_POSTFILEDSIZE_LARGE` and `CURLOPT_COPYPOSTFIELDS` */
    TCOption(PostData),
} CF_SWIFT_NAME(Option);

#pragma mark - Setters

#define ___curl_easy_set_opt(_c, _o, _v, _e) \
    CURLcode code = curl_easy_setopt(_c, _o, _v); \
    if (code != CURLE_OK && _e) { \
        *_e = curl_code_to_error(code); \
    }

#define ARRAY_LENGTH(x) (sizeof(x) / sizeof((x)[0]))

static void curl_easy_set_post_data(CURL * handle, UInt8 data[], CFErrorRef *error) {
    curl_easy_set_opt_long(handle, TCURLOptionPostfieldSize, (int)ARRAY_LENGTH(data), error);
    if (error) { return; }
    curl_easy_set_opt_void(handle, TCURLOptionCopyPostFields, &data, error);
}

static void curl_easy_set_opt_long(CURL * handle, TCURLOption option, long value, CFErrorRef *error)
{
    ___curl_easy_set_opt(handle, option, value, error)
}

static void curl_easy_set_opt_cstr(CURL * handle, TCURLOption option, CString value, CFErrorRef *error)
{
    ___curl_easy_set_opt(handle, option, value, error)
}

static void curl_easy_set_opt_int64(CURL * handle, TCURLOption option, CInt64 value, CFErrorRef *error)
{
    ___curl_easy_set_opt(handle, option, value, error)
}

static void curl_easy_set_opt_slist(CURL * handle, TCURLOption option, CSList value, CFErrorRef *error)
{
    ___curl_easy_set_opt(handle, option, value, error)
}

static void curl_easy_set_opt_void(CURL * handle, TCURLOption option, AnyVoid value, CFErrorRef *error)
{
    ___curl_easy_set_opt(handle, option, value, error)
}

static void curl_easy_set_opt_func(CURL * handle, TCURLOption option, curl_func value, CFErrorRef *error)
{
    ___curl_easy_set_opt(handle, option, value, error)
}

#pragma mark - Getters

#define ___curl_easy_get_info(_c, _i, _e, _v) \
CURLcode code = curl_easy_getinfo(_c, _i, &_v); \
if (code != CURLE_OK && _e) { \
*_e = curl_code_to_error(code); \
} \

static CString curl_easy_get_info_cstr(CURL * handle, CURLINFO info, CFErrorRef *error) {
    CString value; ___curl_easy_get_info(handle, info, error, value); return value;
}

static long curl_easy_get_info_long(CURL * handle, CURLINFO info, CFErrorRef *error) {
    long value; ___curl_easy_get_info(handle, info, error, value); return value;
}

static CInt64 curl_easy_get_info_int64(CURL * handle, CURLINFO info, CFErrorRef *error) {
    CInt64 value; ___curl_easy_get_info(handle, info, error, value); return value;
}

static CSList curl_easy_get_info_list(CURL * handle, CURLINFO info, CFErrorRef *error) {
    CSList value; __curl_easy_get_info(handle, info, error, value); return value;
}

#endif /* _shim_h_ */
