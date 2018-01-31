#ifndef _shim_h_
#define _shim_h_

#include <curl/curl.h>
#include <CoreFoundation/CoreFoundation.h>

#if !defined(CF_SWIFT_NAME)
#define CF_SWIFT_NAME(_name)
#endif

#if !defined(CF_ENUM)
#define CF_ENUM(_type, _name) _type _name ; enum
#endif

#define TOption(_name, _curl_option) TCURLOption##_name = _curl_option

typedef CF_ENUM(int, TCURLOption) {
  /* This is the FILE * or void * the regular output should be written to. */
  TOption(WriteData, CURLOPT_WRITEDATA),

  /* The full URL to get/put */
  TOption(URL, CURLOPT_URL),

  /* Port number to connect to, if other than default. */
  TOption(Port, CURLOPT_PORT),

  /* Name of proxy to use. */
  TOption(Proxy, CURLOPT_PROXY),

  /* "user:password;options" to use when fetching. */
  TOption(UserAndPassword, CURLOPT_USERPWD),

  /* "user:password" to use with proxy. */
  TOption(ProxyUserPassword, CURLOPT_PROXYUSERPWD),

  /* Range to get, specified as an ASCII string. */
  TOption(Range, CURLOPT_RANGE),

  /* Specified file stream to upload from (use as input): */
  TOption(ReadData, CURLOPT_READDATA),

  /* Buffer to receive error messages in, must be at least CURL_ERROR_SIZE
   * bytes big. If this is not used, error messages go to stderr instead: */
  TOption(ErrorBuffer, CURLOPT_ERRORBUFFER),

  /* Function that will be called to store the output (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  TOption(WriteFunction, CURLOPT_WRITEFUNCTION),

  /* Function that will be called to read the input (instead of fread). The
   * parameters will use fread() syntax, make sure to follow them. */
  TOption(ReadFunction, CURLOPT_READFUNCTION),

  /* Time-out the read operation after this amount of seconds */
  TOption(Timeout, CURLOPT_TIMEOUT),

  /* If the CURLOPT_INFILE is used, this can be used to inform libcurl about
   * how large the file being sent really is. That allows better error
   * checking and better verifies that the upload was successful. -1 means
   * unknown size.
   *
   * For large file support, there is also a _LARGE version of the key
   * which takes an off_t type, allowing platforms with larger off_t
   * sizes to handle larger files.  See below for INFILESIZE_LARGE.
   */
  TOption(InfileSize, CURLOPT_INFILESIZE),

  /* POST static input fields. */
  TOption(PostFields, CURLOPT_POSTFIELDS),

  /* Set the referrer page (needed by some CGIs) */
  TOption(Referrer, CURLOPT_REFERER),

  /* Set the FTP PORT string (interface name, named or numerical IP address)
     Use i.e '-' to use default address. */
  TOption(FTTPort, CURLOPT_FTPPORT) CF_SWIFT_NAME(FTPPort),

  /* Set the User-Agent string (examined by some CGIs) */
  TOption(UserAgent, CURLOPT_USERAGENT),

  /* If the download receives less than "low speed limit" bytes/second
   * during "low speed time" seconds, the operations is aborted.
   * You could i.e if you have a pretty high speed connection, abort if
   * it is less than 2000 bytes/sec during 20 seconds.
   */

  /* Set the "low speed limit" */
  TOption(LowSpeedLimit, CURLOPT_LOW_SPEED_LIMIT),

  /* Set the "low speed time" */
  TOption(LowSpeedLimitTime, CURLOPT_LOW_SPEED_TIME),

  /* Set the continuation offset.
   *
   * Note there is also a _LARGE version of this key which uses
   * off_t types, allowing for large file offsets on platforms which
   * use larger-than-32-bit off_t's.  Look below for RESUME_FROM_LARGE.
   */
  TOption(ResumeFrom, CURLOPT_RESUME_FROM),

  /* Set cookie in request: */
  TOption(Cookie, CURLOPT_COOKIE),

  /* This points to a linked list of headers, struct curl_slist kind. This
     list is also used for RTSP (in spite of its name) */
  TOption(HTTPHeader, CURLOPT_HTTPHEADER) CF_SWIFT_NAME(HTTPHeader),

  /* This points to a linked list of post entries, struct curl_httppost */
  TOption(HTTPPost, CURLOPT_HTTPPOST) CF_SWIFT_NAME(HTTPPost),

  /* name of the file keeping your private SSL-certificate */
  TOption(SSLCert, CURLOPT_SSLCERT) CF_SWIFT_NAME(sslCert),

  /* password for the SSL or SSH private key */
  TOption(KeyPassword, CURLOPT_KEYPASSWD),

  /* send TYPE parameter? */
  TOption(CLRF, CURLOPT_CRLF) CF_SWIFT_NAME(CLRF),

  /* send linked-list of QUOTE commands */
  TOption(Quote, CURLOPT_QUOTE),

  /* send FILE * or void * to store headers to, if you use a callback it
     is simply passed to the callback unmodified */
  TOption(HeaderData, CURLOPT_HEADERDATA),

  /* point to a file to read the initial cookies from, also enables
     "cookie awareness" */
  TOption(CookieFile, CURLOPT_COOKIEFILE),

  /* What version to specifically try to use.
     See CURL_SSLVERSION defines below. */
  TOption(SSLVersion, CURLOPT_SSLVERSION) CF_SWIFT_NAME(sslVersion),

  /* What kind of HTTP time condition to use, see defines */
  TOption(TimeCondition, CURLOPT_TIMECONDITION),

  /* Time to use with the above condition. Specified in number of seconds
     since 1 Jan 1970 */
  TOption(TimeValue, CURLOPT_TIMEVALUE),

  /* 35 = OBSOLETE */

  /* Custom request, for customizing the get command like
     HTTP: DELETE, TRACE and others
     FTP: to use a different list command
     */
  TOption(CustomRequest, CURLOPT_CUSTOMREQUEST),

  /* FILE handle to use instead of stderr */
  TOption(Stderr, CURLOPT_STDERR),

  /* 38 is not used */

  /* send linked-list of post-transfer QUOTE commands */
  TOption(PostQuote, CURLOPT_POSTQUOTE),

  TOption(Verbose, CURLOPT_VERBOSE),      /* talk a lot */
  TOption(Header, CURLOPT_HEADER),       /* throw the header out too */
  TOption(NoProgress, CURLOPT_NOPROGRESS),   /* shut off the progress meter */
  TOption(Nobody, CURLOPT_NOBODY),       /* use HEAD to get http document */
  TOption(FailOnError, CURLOPT_FAILONERROR),  /* no output on http error codes >= 400 */
  TOption(Upload, CURLOPT_UPLOAD),       /* this is an upload */
  TOption(Post, CURLOPT_POST),         /* HTTP POST method */
  TOption(DirListOnly, CURLOPT_DIRLISTONLY),  /* bare names when listing directories */

  TOption(Append, CURLOPT_APPEND),       /* Append instead of overwrite on upload! */

  /* Specify whether to read the user+password from the .netrc or the URL.
   * This must be one of the CURL_NETRC_* enums below. */
  TOption(Netrc, CURLOPT_NETRC),

  TOption(FollowLocation, CURLOPT_FOLLOWLOCATION),  /* use Location: Luke! */

  TOption(TransferText, CURLOPT_TRANSFERTEXT), /* transfer data in text/ASCII format */
  TOption(Put, CURLOPT_PUT),          /* HTTP PUT */

  /* 55 = OBSOLETE */

  /* DEPRECATED
   * Function that will be called instead of the internal progress display
   * function. This function should be defined as the curl_progress_callback
   * prototype defines. */
  TOption(ProgressFunction, CURLOPT_PROGRESSFUNCTION),

  /* Data passed to the CURLOPT_PROGRESSFUNCTION and CURLOPT_XFERINFOFUNCTION
     callbacks */
  TOption(ProgressData, CURLOPT_PROGRESSDATA),

  /* We want the referrer field set automatically when following locations */
  TOption(AutoReferer, CURLOPT_AUTOREFERER),

  /* Port of the proxy, can be set in the proxy string as well with:
     "[host]:[port]" */
  TOption(ProxyPort, CURLOPT_PROXYPORT),

  /* size of the POST input data, if strlen() is not good to use */
  TOption(PostfieldSize, CURLOPT_POSTFIELDSIZE),

  /* tunnel non-http operations through a HTTP proxy */
  TOption(HTTPProxyTunnel, CURLOPT_HTTPPROXYTUNNEL),

  /* Set the interface string to use as outgoing network interface */
  TOption(Interface, CURLOPT_INTERFACE),

  /* Set the krb4/5 security level, this also enables krb4/5 awareness.  This
   * is a string, 'clear', 'safe', 'confidential' or 'private'.  If the string
   * is set but doesn't match one of these, 'private' will be used.  */
  TOption(KrbLevel, CURLOPT_KRBLEVEL),

  /* Set if we should verify the peer in ssl handshake, set 1 to verify. */
  TOption(SSLVerifyPeer, CURLOPT_SSL_VERIFYPEER) CF_SWIFT_NAME(sslVerifyPeer),

  /* The CApath or CAfile used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  TOption(CAInfo, CURLOPT_CAINFO),

  /* Maximum number of http redirects to follow */
  TOption(MaxRedirs, CURLOPT_MAXREDIRS),

  /* Pass a long set to 1 to get the date of the requested document (if
     possible)! Pass a zero to shut it off. */
  TOption(FileTime, CURLOPT_FILETIME),

  /* This points to a linked list of telnet options */
  TOption(TelnetOptions, CURLOPT_TELNETOPTIONS),

  /* Max amount of cached alive connections */
  TOption(MaxConnects, CURLOPT_MAXCONNECTS),

  /* Set to explicitly use a new connection for the upcoming transfer.
     Do not use this unless you're absolutely sure of this, as it makes the
     operation slower and is less friendly for the network. */
  TOption(FreshConnect, CURLOPT_FRESH_CONNECT),

  /* Set to explicitly forbid the upcoming transfer's connection to be re-used
     when done. Do not use this unless you're absolutely sure of this, as it
     makes the operation slower and is less friendly for the network. */
  TOption(ForbidReuse, CURLOPT_FORBID_REUSE),

  /* Set to a file name that contains random data for libcurl to use to
     seed the random engine when doing SSL connects. */
  TOption(RandomFile, CURLOPT_RANDOM_FILE),

  /* Set to the Entropy Gathering Daemon socket pathname */
  TOption(EGDSocket, CURLOPT_EGDSOCKET),

  /* Time-out connect operations after this amount of seconds, if connects are
     OK within this time, then fine... This only aborts the connect phase. */
  TOption(ConnectTimeout, CURLOPT_CONNECTTIMEOUT),

  /* Function that will be called to store headers (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  TOption(HeaderFunction, CURLOPT_HEADERFUNCTION),

  /* Set this to force the HTTP request to get back to GET. Only really usable
     if POST, PUT or a custom request have been used first.
   */
  TOption(HTTPGet, CURLOPT_HTTPGET),

  /* Set if we should verify the Common name from the peer certificate in ssl
   * handshake, set 1 to check existence, 2 to ensure that it matches the
   * provided hostname. */
  TOption(SSLVerifyHost, CURLOPT_SSL_VERIFYHOST) CF_SWIFT_NAME(sslVerifyHost),

  /* Specify which file name to write all known cookies in after completed
     operation. Set file name to "-" (dash) to make it go to stdout. */
  TOption(CookieJar, CURLOPT_COOKIEJAR),

  /* Specify which SSL ciphers to use */
  TOption(SSLCipherList, CURLOPT_SSL_CIPHER_LIST) CF_SWIFT_NAME(sslCipherList),

  /* Specify which HTTP version to use! This must be set to one of the
     CURL_HTTP_VERSION* enums set below. */
  TOption(HTTPVersion, CURLOPT_HTTP_VERSION),

  /* Specifically switch on or off the FTP engine's use of the EPSV command. By
     default, that one will always be attempted before the more traditional
     PASV command. */
  TOption(FTPUseEPSV, CURLOPT_FTP_USE_EPSV),

  /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") */
  TOption(SSLCertType, CURLOPT_SSLCERTTYPE) CF_SWIFT_NAME(sslCertType),

  /* name of the file keeping your private SSL-key */
  TOption(SSLKey, CURLOPT_SSLKEY) CF_SWIFT_NAME(sslKey),

  /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") */
  TOption(SSLKeyType, CURLOPT_SSLKEYTYPE) CF_SWIFT_NAME(sslKeyType),

  /* crypto engine for the SSL-sub system */
  TOption(SSLEngine, CURLOPT_SSLENGINE) CF_SWIFT_NAME(sslEngine),

  /* set the crypto engine for the SSL-sub system as default
     the param has no meaning...
   */
  TOption(SSLEngineDefault, CURLOPT_SSLENGINE_DEFAULT) CF_SWIFT_NAME(sslEngineDefault),

  /* Non-zero value means to use the global dns cache */
  TOption(DNSUseGlobalCache, CURLOPT_DNS_USE_GLOBAL_CACHE), /* DEPRECATED, do not use! */

  /* DNS cache timeout */
  TOption(DNSCacheTimeout, CURLOPT_DNS_CACHE_TIMEOUT),

  /* send linked-list of pre-transfer QUOTE commands */
  TOption(PreQuote, CURLOPT_PREQUOTE),

  /* set the debug function */
  TOption(DebugFunction, CURLOPT_DEBUGFUNCTION),

  /* set the data for the debug function */
  TOption(DebugData, CURLOPT_DEBUGDATA),

  /* mark this as start of a cookie session */
  TOption(CookieSession, CURLOPT_COOKIESESSION),

  /* The CApath directory used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  TOption(CAPath, CURLOPT_CAPATH),

  /* Instruct libcurl to use a smaller receive buffer */
  TOption(BufferSize, CURLOPT_BUFFERSIZE),

  /* Instruct libcurl to not use any signal/alarm handlers, even when using
     timeouts. This option is useful for multi-threaded applications.
     See libcurl-the-guide for more background information. */
  TOption(NoSignal, CURLOPT_NOSIGNAL),

  /* Provide a CURLShare for mutexing non-ts data */
  TOption(Share, CURLOPT_SHARE),

  /* indicates type of proxy. accepted values are CURLPROXY_HTTP (default),
     CURLPROXY_HTTPS, CURLPROXY_SOCKS4, CURLPROXY_SOCKS4A and
     CURLPROXY_SOCKS5. */
  TOption(ProxyType, CURLOPT_PROXYTYPE),

  /* Set the Accept-Encoding string. Use this to tell a server you would like
     the response to be compressed. Before 7.21.6, this was known as
     CURLOPT_ENCODING */
  TOption(AcceptEncoding, CURLOPT_ACCEPT_ENCODING),

  /* Set pointer to private data */
  TOption(Private, CURLOPT_PRIVATE),

  /* Set aliases for HTTP 200 in the HTTP Response header */
  TOption(HTTP200Aliases, CURLOPT_HTTP200ALIASES),

  /* Continue to send authentication (user+password) when following locations,
     even when hostname changed. This can potentially send off the name
     and password to whatever host the server decides. */
  TOption(UnrestrictedAuth, CURLOPT_UNRESTRICTED_AUTH),

  /* Specifically switch on or off the FTP engine's use of the EPRT command (
     it also disables the LPRT attempt). By default, those ones will always be
     attempted before the good old traditional PORT command. */
  TOption(FTPUseEPRT, CURLOPT_FTP_USE_EPRT),

  /* Set this to a bitmask value to enable the particular authentications
     methods you like. Use this in combination with CURLOPT_USERPWD.
     Note that setting multiple bits may cause extra network round-trips. */
  TOption(HTTPAuth, CURLOPT_HTTPAUTH),

  /* Set the ssl context callback function, currently only for OpenSSL ssl_ctx
     in second argument. The function must be matching the
     curl_ssl_ctx_callback proto. */
  TOption(SSLCtxFunction, CURLOPT_SSL_CTX_FUNCTION) CF_SWIFT_NAME(sslCtxFunction),

  /* Set the userdata for the ssl context callback function's third
     argument */
  TOption(SSLCtxData, CURLOPT_SSL_CTX_DATA) CF_SWIFT_NAME(sslCtxData),

  /* FTP Option that causes missing dirs to be created on the remote server.
     In 7.19.4 we introduced the convenience enums for this option using the
     CURLFTP_CREATE_DIR prefix.
  */
  TOption(FTPCreateMissingDirs, CURLOPT_FTP_CREATE_MISSING_DIRS),

  /* Set this to a bitmask value to enable the particular authentications
     methods you like. Use this in combination with CURLOPT_PROXYUSERPWD.
     Note that setting multiple bits may cause extra network round-trips. */
  TOption(ProxyAuth, CURLOPT_PROXYAUTH),

  /* FTP option that changes the timeout, in seconds, associated with
     getting a response.  This is different from transfer timeout time and
     essentially places a demand on the FTP server to acknowledge commands
     in a timely manner. */
  TOption(FTPResponseTimeout, CURLOPT_FTP_RESPONSE_TIMEOUT),

  /* Set this option to one of the CURL_IPRESOLVE_* defines (see below) to
     tell libcurl to resolve names to those IP versions only. This only has
     affect on systems with support for more than one, i.e IPv4 _and_ IPv6. */
  TOption(IPResolve, CURLOPT_IPRESOLVE),

  /* Set this option to limit the size of a file that will be downloaded from
     an HTTP or FTP server.

     Note there is also _LARGE version which adds large file support for
     platforms which have larger off_t sizes.  See MAXFILESIZE_LARGE below. */
  TOption(MaxFilesize, CURLOPT_MAXFILESIZE),

  /* See the comment for INFILESIZE above, but in short, specifies
   * the size of the file being uploaded.  -1 means unknown.
   */
  TOption(InFilesizeLarge, CURLOPT_INFILESIZE_LARGE),

  /* Sets the continuation offset.  There is also a LONG version of this;
   * look above for RESUME_FROM.
   */
  TOption(ResumeFromLarge, CURLOPT_RESUME_FROM_LARGE),

  /* Sets the maximum size of data that will be downloaded from
   * an HTTP or FTP server.  See MAXFILESIZE above for the LONG version.
   */
  TOption(MaxFilesizeLarge, CURLOPT_MAXFILESIZE_LARGE),

  /* Set this option to the file name of your .netrc file you want libcurl
     to parse (using the CURLOPT_NETRC option). If not set, libcurl will do
     a poor attempt to find the user's home directory and check for a .netrc
     file in there. */
  TOption(NetrcFile, CURLOPT_NETRC_FILE),

  /* Enable SSL/TLS for FTP, pick one of:
     CURLUSESSL_TRY     - try using SSL, proceed anyway otherwise
     CURLUSESSL_CONTROL - SSL for the control connection or fail
     CURLUSESSL_ALL     - SSL for all communication or fail
  */
  TOption(UseSSL, CURLOPT_USE_SSL),

  /* The _LARGE version of the standard POSTFIELDSIZE option */
  TOption(PostFieldsizeLarge, CURLOPT_POSTFIELDSIZE_LARGE),

  /* Enable/disable the TCP Nagle algorithm */
  TOption(TCpPNodelay, CURLOPT_TCP_NODELAY),

  /* When FTP over SSL/TLS is selected (with CURLOPT_USE_SSL), this option
     can be used to change libcurl's default action which is to first try
     "AUTH SSL" and then "AUTH TLS" in this order, and proceed when a OK
     response has been received.

     Available parameters are:
     CURLFTPAUTH_DEFAULT - let libcurl decide
     CURLFTPAUTH_SSL     - try "AUTH SSL" first, then TLS
     CURLFTPAUTH_TLS     - try "AUTH TLS" first, then SSL
  */
  TOption(FTPSSLAuth, CURLOPT_FTPSSLAUTH),

  TOption(IoctlFunction, CURLOPT_IOCTLFUNCTION),
  TOption(IoctlData, CURLOPT_IOCTLDATA),

  /* zero terminated string for pass on to the FTP server when asked for
     "account" info */
  TOption(FTPAccount, CURLOPT_FTP_ACCOUNT),

  /* feed cookie into cookie engine */
  TOption(CookieList, CURLOPT_COOKIELIST),

  /* ignore Content-Length */
  TOption(IgnoreContentLength, CURLOPT_IGNORE_CONTENT_LENGTH),

  /* Set to non-zero to skip the IP address received in a 227 PASV FTP server
     response. Typically used for FTP-SSL purposes but is not restricted to
     that. libcurl will then instead use the same IP address it used for the
     control connection. */
  TOption(FTPSkipPasvIP, CURLOPT_FTP_SKIP_PASV_IP),

  /* Select "file method" to use when doing FTP, see the curl_ftpmethod
     above. */
  TOption(FTPFileMethod, CURLOPT_FTP_FILEMETHOD),

  /* Local port number to bind the socket to */
  TOption(LocalPort, CURLOPT_LOCALPORT),

  /* Number of ports to try, including the first one set with LOCALPORT.
     Thus, setting it to 1 will make no additional attempts but the first.
  */
  TOption(LocalPortRange, CURLOPT_LOCALPORTRANGE),

  /* no transfer, set up connection and let application use the socket by
     extracting it with CURLINFO_LASTSOCKET */
  TOption(ConnectOnly, CURLOPT_CONNECT_ONLY),

  /* Function that will be called to convert from the
     network encoding (instead of using the iconv calls in libcurl) */
  TOption(ConvFromNetworkFunction, CURLOPT_CONV_FROM_NETWORK_FUNCTION),

  /* Function that will be called to convert to the
     network encoding (instead of using the iconv calls in libcurl) */
  TOption(ConvToNetworkFunction, CURLOPT_CONV_TO_NETWORK_FUNCTION),

  /* Function that will be called to convert from UTF8
     (instead of using the iconv calls in libcurl)
     Note that this is used only for SSL certificate processing */
  TOption(ConvFromUtf8Function, CURLOPT_CONV_FROM_UTF8_FUNCTION),

  /* if the connection proceeds too quickly then need to slow it down */
  /* limit-rate: maximum number of bytes per second to send or receive */
  TOption(MaxSendSpeedLarge, CURLOPT_MAX_SEND_SPEED_LARGE),
  TOption(MaxRecvSpeedLarge, CURLOPT_MAX_RECV_SPEED_LARGE),

  /* Pointer to command string to send if USER/PASS fails. */
  TOption(FTPAlternativeToUser, CURLOPT_FTP_ALTERNATIVE_TO_USER),

  /* callback function for setting socket options */
  TOption(SockOptFunction, CURLOPT_SOCKOPTFUNCTION),
  TOption(SockOptData, CURLOPT_SOCKOPTDATA),

  /* set to 0 to disable session ID re-use for this transfer, default is
     enabled (== 1) */
  TOption(SSLSessionidCache, CURLOPT_SSL_SESSIONID_CACHE),

  /* allowed SSH authentication methods */
  TOption(SSHAuthTypes, CURLOPT_SSH_AUTH_TYPES),

  /* Used by scp/sftp to do public/private key authentication */
  TOption(SSHPublicKeyfile, CURLOPT_SSH_PUBLIC_KEYFILE),
  TOption(SSHPrivateKeyfile, CURLOPT_SSH_PRIVATE_KEYFILE),

  /* Send CCC (Clear Command Channel) after authentication */
  TOption(FTPSSLCcc, CURLOPT_FTP_SSL_CCC),

  /* Same as TIMEOUT and CONNECTTIMEOUT, but with ms resolution */
  TOption(TimeoutMs, CURLOPT_TIMEOUT_MS),
  TOption(ConnectTimeoutMs, CURLOPT_CONNECTTIMEOUT_MS),

  /* set to zero to disable the libcurl's decoding and thus pass the raw body
     data to the application even when it is encoded/compressed */
  TOption(HTTPTransferDecoding, CURLOPT_HTTP_TRANSFER_DECODING),
  TOption(HTTPContentDecoding, CURLOPT_HTTP_CONTENT_DECODING),

  /* Permission used when creating new files and directories on the remote
     server for protocols that support it, SFTP/SCP/FILE */
  TOption(NewFilePerms, CURLOPT_NEW_FILE_PERMS),
  TOption(NewDirectoryPerms, CURLOPT_NEW_DIRECTORY_PERMS),

  /* Set the behaviour of POST when redirecting. Values must be set to one
     of CURL_REDIR* defines below. This used to be called CURLOPT_POST301 */
  TOption(PostRedir, CURLOPT_POSTREDIR),

  /* used by scp/sftp to verify the host's public key */
  TOption(SSHHostPublicKeyMd5, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5),

  /* Callback function for opening socket (instead of socket(2)). Optionally,
     callback is able change the address or refuse to connect returning
     CURL_SOCKET_BAD.  The callback should have type
     curl_opensocket_callback */
  TOption(OpenSocketFunction, CURLOPT_OPENSOCKETFUNCTION),
  TOption(OpenSocketData, CURLOPT_OPENSOCKETDATA),

  /* POST volatile input fields. */
  TOption(CopyPostFields, CURLOPT_COPYPOSTFIELDS),

  /* set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy */
  TOption(ProxyTransferMode, CURLOPT_PROXY_TRANSFER_MODE),

  /* Callback function for seeking in the input stream */
  TOption(SeekFunction, CURLOPT_SEEKFUNCTION),
  TOption(SeekData, CURLOPT_SEEKDATA),

  /* CRL file */
  TOption(CrlFile, CURLOPT_CRLFILE),

  /* Issuer certificate */
  TOption(IssuerCert, CURLOPT_ISSUERCERT),

  /* (IPv6) Address scope */
  TOption(AddressScope, CURLOPT_ADDRESS_SCOPE),

  /* Collect certificate chain info and allow it to get retrievable with
     CURLINFO_CERTINFO after the transfer is complete. */
  TOption(CertInfo, CURLOPT_CERTINFO),

  /* "name" and "pwd" to use when fetching. */
  TOption(Username, CURLOPT_USERNAME),
  TOption(Password, CURLOPT_PASSWORD),

    /* "name" and "pwd" to use with Proxy when fetching. */
  TOption(ProxyUsername, CURLOPT_PROXYUSERNAME),
  TOption(ProxyPassword, CURLOPT_PROXYPASSWORD),

  /* Comma separated list of hostnames defining no-proxy zones. These should
     match both hostnames directly, and hostnames within a domain. For
     example, local.com will match local.com and www.local.com, but NOT
     notlocal.com or www.notlocal.com. For compatibility with other
     implementations of this, .local.com will be considered to be the same as
     local.com. A single * is the only valid wildcard, and effectively
     disables the use of proxy. */
  TOption(NoProxy, CURLOPT_NOPROXY),

  /* block size for TFTP transfers */
  TOption(TFTPBlockSize, CURLOPT_TFTP_BLKSIZE),

  /* Socks Service */
  TOption(Socks5GssapiNec, CURLOPT_SOCKS5_GSSAPI_NEC),

  /* set the bitmask for the protocols that are allowed to be used for the
     transfer, which thus helps the app which takes URLs from users or other
     external inputs and want to restrict what protocol(s) to deal
     with. Defaults to CURLPROTO_ALL. */
  TOption(Protocols, CURLOPT_PROTOCOLS),

  /* set the bitmask for the protocols that libcurl is allowed to follow to,
     as a subset of the CURLOPT_PROTOCOLS ones. That means the protocol needs
     to be set in both bitmasks to be allowed to get redirected to. Defaults
     to all protocols except FILE and SCP. */
  TOption(RedirProtocols, CURLOPT_REDIR_PROTOCOLS),

  /* set the SSH knownhost file name to use */
  TOption(SSHKnownhosts, CURLOPT_SSH_KNOWNHOSTS),

  /* set the SSH host key callback, must point to a curl_sshkeycallback
     function */
  TOption(SSHKeyfunction, CURLOPT_SSH_KEYFUNCTION),

  /* set the SSH host key callback custom pointer */
  TOption(SSHKeydata, CURLOPT_SSH_KEYDATA),

  /* set the SMTP mail originator */
  TOption(MailFrom, CURLOPT_MAIL_FROM),

  /* set the list of SMTP mail receiver(s) */
  TOption(MailRcpt, CURLOPT_MAIL_RCPT),

  /* FTP: send PRET before PASV */
  TOption(FTPUsePret, CURLOPT_FTP_USE_PRET),

  /* RTSP request method (OPTIONS, SETUP, PLAY, etc...) */
  TOption(RtspRequest, CURLOPT_RTSP_REQUEST),

  /* The RTSP session identifier */
  TOption(RtspSessionId, CURLOPT_RTSP_SESSION_ID),

  /* The RTSP stream URI */
  TOption(RtspStreamUri, CURLOPT_RTSP_STREAM_URI),

  /* The Transport: header to use in RTSP requests */
  TOption(RtspTransport, CURLOPT_RTSP_TRANSPORT),

  /* Manually initialize the client RTSP CSeq for this handle */
  TOption(RtspClientCseq, CURLOPT_RTSP_CLIENT_CSEQ),

  /* Manually initialize the server RTSP CSeq for this handle */
  TOption(RtspServerCseq, CURLOPT_RTSP_SERVER_CSEQ),

  /* The stream to pass to INTERLEAVEFUNCTION. */
  TOption(InterLeaveData, CURLOPT_INTERLEAVEDATA),

  /* Let the application define a custom write method for RTP data */
  TOption(InterLeaveFunction, CURLOPT_INTERLEAVEFUNCTION),

  /* Turn on wildcard matching */
  TOption(WildcardMatch, CURLOPT_WILDCARDMATCH),

  /* Directory matching callback called before downloading of an
     individual file (chunk) started */
  TOption(ChunkBgnFunction, CURLOPT_CHUNK_BGN_FUNCTION),

  /* Directory matching callback called after the file (chunk)
     was downloaded, or skipped */
  TOption(ChunkEndFunction, CURLOPT_CHUNK_END_FUNCTION),

  /* Change match (fnmatch-like) callback for wildcard matching */
  TOption(FnmatchFunction, CURLOPT_FNMATCH_FUNCTION),

  /* Let the application define custom chunk data pointer */
  TOption(ChunkData, CURLOPT_CHUNK_DATA),

  /* FNMATCH_FUNCTION user pointer */
  TOption(FnmatchData, CURLOPT_FNMATCH_DATA),

  /* send linked-list of name:port:address sets */
  TOption(Resolve, CURLOPT_RESOLVE),

  /* Set a username for authenticated TLS */
  TOption(TLSAuthUsername, CURLOPT_TLSAUTH_USERNAME),

  /* Set a password for authenticated TLS */
  TOption(TLSAuthPassword, CURLOPT_TLSAUTH_PASSWORD),

  /* Set authentication type for authenticated TLS */
  TOption(TLSAuthType, CURLOPT_TLSAUTH_TYPE),

  /* Set to 1 to enable the "TE:" header in HTTP requests to ask for
     compressed transfer-encoded responses. Set to 0 to disable the use of TE:
     in outgoing requests. The current default is 0, but it might change in a
     future libcurl release.

     libcurl will ask for the compressed methods it knows of, and if that
     isn't any, it will not ask for transfer-encoding at all even if this
     option is set to 1.

  */
  TOption(TransferEncoding, CURLOPT_TRANSFER_ENCODING),

  /* Callback function for closing socket (instead of close(2)). The callback
     should have type curl_closesocket_callback */
  TOption(CloseSocketFunction, CURLOPT_CLOSESOCKETFUNCTION),
  TOption(CloseSocketData, CURLOPT_CLOSESOCKETDATA),

  /* allow GSSAPI credential delegation */
  TOption(GssapiDelegation, CURLOPT_GSSAPI_DELEGATION),

  /* Set the name servers to use for DNS resolution */
  TOption(DnsServers, CURLOPT_DNS_SERVERS),

  /* Time-out accept operations (currently for FTP only) after this amount
     of milliseconds. */
  TOption(AcceptTimeoutMs, CURLOPT_ACCEPTTIMEOUT_MS),

  /* Set TCP keepalive */
  TOption(TCPKeepAlive, CURLOPT_TCP_KEEPALIVE) CF_SWIFT_NAME(tcpKeepAlive),

  /* non-universal keepalive knobs (Linux, AIX, HP-UX, more) */
  TOption(TCPKeepIdle, CURLOPT_TCP_KEEPIDLE) CF_SWIFT_NAME(tcpKeepIdle),
  TOption(TCPKeepIntvl, CURLOPT_TCP_KEEPINTVL) CF_SWIFT_NAME(tcpKeepIntvl),

  /* Enable/disable specific SSL features with a bitmask, see CURLSSLOPT_* */
  TOption(SSLOptions, CURLOPT_SSL_OPTIONS),

  /* Set the SMTP auth originator */
  TOption(MailAuth, CURLOPT_MAIL_AUTH),

  /* Enable/disable SASL initial response */
  TOption(SASLInternalResponse, CURLOPT_SASL_IR),

  /* Function that will be called instead of the internal progress display
   * function. This function should be defined as the curl_xferinfo_callback
   * prototype defines. (Deprecates CURLOPT_PROGRESSFUNCTION) */
  TOption(Xferinfofunction, CURLOPT_XFERINFOFUNCTION),

  /* The XOAUTH2 bearer token */
  TOption(XOAuth2Bearer, CURLOPT_XOAUTH2_BEARER),

  /* Set the interface string to use as outgoing network
   * interface for DNS requests.
   * Only supported by the c-ares DNS backend */
  TOption(DNSInterface, CURLOPT_DNS_INTERFACE),

  /* Set the local IPv4 address to use for outgoing DNS requests.
   * Only supported by the c-ares DNS backend */
  TOption(DnsLocalIP4, CURLOPT_DNS_LOCAL_IP4),

  /* Set the local IPv4 address to use for outgoing DNS requests.
   * Only supported by the c-ares DNS backend */
  TOption(DnsLocalIP6, CURLOPT_DNS_LOCAL_IP6),

  /* Set authentication options directly */
  TOption(LoginOptions, CURLOPT_LOGIN_OPTIONS),

  /* Enable/disable TLS NPN extension (http2 over ssl might fail without) */
  TOption(SSLEnableNpn, CURLOPT_SSL_ENABLE_NPN),

  /* Enable/disable TLS ALPN extension (http2 over ssl might fail without) */
  TOption(SSLEnableAlpn, CURLOPT_SSL_ENABLE_ALPN),

  /* Time to wait for a response to a HTTP request containing an
   * Expect: 100-continue header before sending the data anyway. */
  TOption(Expect100TimeoutMs, CURLOPT_EXPECT_100_TIMEOUT_MS),

  /* This points to a linked list of headers used for proxy requests only,
     struct curl_slist kind */
  TOption(ProxyHeader, CURLOPT_PROXYHEADER),

  /* Pass in a bitmask of "header options" */
  TOption(HeaderOpt, CURLOPT_HEADEROPT),

  /* The public key in DER form used to validate the peer public key
     this option is used only if SSL_VERIFYPEER is true */
  TOption(PinnedPublicKey, CURLOPT_PINNEDPUBLICKEY),

  /* Path to Unix domain socket */
  TOption(UnixSocketPath, CURLOPT_UNIX_SOCKET_PATH),

  /* Set if we should verify the certificate status. */
  TOption(SSLVerifyStatus, CURLOPT_SSL_VERIFYSTATUS),

  /* Set if we should enable TLS false start. */
  TOption(SSLFalseStart, CURLOPT_SSL_FALSESTART),

  /* Do not squash dot-dot sequences */
  TOption(PathAsIs, CURLOPT_PATH_AS_IS),

  /* Proxy Service Name */
  TOption(ProxyServiceName, CURLOPT_PROXY_SERVICE_NAME),

  /* Service Name */
  TOption(ServiceName, CURLOPT_SERVICE_NAME),

  /* Wait/don't wait for pipe/mutex to clarify */
  TOption(PipeWait, CURLOPT_PIPEWAIT),

  /* Set the protocol used when curl is given a URL without a protocol */
  TOption(DefaultProtocol, CURLOPT_DEFAULT_PROTOCOL),

  /* Set stream weight, 1 - 256 (default is 16) */
  TOption(StreamWeight, CURLOPT_STREAM_WEIGHT),

  /* Set stream dependency on another CURL handle */
  TOption(StreamDepends, CURLOPT_STREAM_DEPENDS),

  /* Set E-xclusive stream dependency on another CURL handle */
  TOption(StreamDependsE, CURLOPT_STREAM_DEPENDS_E),

  /* Do not send any tftp option requests to the server */
  TOption(TFPTNoOptions, CURLOPT_TFTP_NO_OPTIONS),

  /* Linked-list of host:port:connect-to-host:connect-to-port,
     overrides the URL's host:port (only for the network layer) */
  TOption(ConnectTo, CURLOPT_CONNECT_TO),

  /* Set TCP Fast Open */
  TOption(TCPFastOpen, CURLOPT_TCP_FASTOPEN) CF_SWIFT_NAME(tcpFastOpen),

  /* Continue to send data if the server responds early with an
   * HTTP status code >= 300 */
  TOption(KeepSendingOnError, CURLOPT_KEEP_SENDING_ON_ERROR),

  /* The CApath or CAfile used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  TOption(ProxyCAInfo, CURLOPT_PROXY_CAINFO),

  /* The CApath directory used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  TOption(ProxyCAPath, CURLOPT_PROXY_CAPATH),

  /* Set if we should verify the proxy in ssl handshake,
     set 1 to verify. */
  TOption(ProxySSLVerifyPeer, CURLOPT_PROXY_SSL_VERIFYPEER),

  /* Set if we should verify the Common name from the proxy certificate in ssl
   * handshake, set 1 to check existence, 2 to ensure that it matches
   * the provided hostname. */
  TOption(ProxySSLVerifyHost, CURLOPT_PROXY_SSL_VERIFYHOST),

  /* What version to specifically try to use for proxy.
     See CURL_SSLVERSION defines below. */
  TOption(ProxySSLVersion, CURLOPT_PROXY_SSLVERSION),

  /* Set a username for authenticated TLS for proxy */
  TOption(ProxyTLSAuthUsername, CURLOPT_PROXY_TLSAUTH_USERNAME),

  /* Set a password for authenticated TLS for proxy */
  TOption(ProxyTLSAuthPassword, CURLOPT_PROXY_TLSAUTH_PASSWORD),

  /* Set authentication type for authenticated TLS for proxy */
  TOption(ProxyTLSAuthType, CURLOPT_PROXY_TLSAUTH_TYPE),

  /* name of the file keeping your private SSL-certificate for proxy */
  TOption(ProxySSLCert, CURLOPT_PROXY_SSLCERT),

  /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") for
     proxy */
  TOption(ProxySSLCerttype, CURLOPT_PROXY_SSLCERTTYPE),

  /* name of the file keeping your private SSL-key for proxy */
  TOption(ProxySSLKey, CURLOPT_PROXY_SSLKEY),

  /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") for
     proxy */
  TOption(ProxySSLKeyType, CURLOPT_PROXY_SSLKEYTYPE),

  /* password for the SSL private key for proxy */
  TOption(ProxyKeyPassword, CURLOPT_PROXY_KEYPASSWD),

  /* Specify which SSL ciphers to use for proxy */
  TOption(ProxySSLCipherList, CURLOPT_PROXY_SSL_CIPHER_LIST),

  /* CRL file for proxy */
  TOption(ProxyCRLFile, CURLOPT_PROXY_CRLFILE),

  /* Enable/disable specific SSL features with a bitmask for proxy, see
     CURLSSLOPT_* */
  TOption(ProxySSLOptions, CURLOPT_PROXY_SSL_OPTIONS),

  /* Name of pre proxy to use. */
  TOption(PreProxy, CURLOPT_PRE_PROXY),

  /* The public key in DER form used to validate the proxy public key
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  TOption(ProxyPinnedPublicKey, CURLOPT_PROXY_PINNEDPUBLICKEY),

  /* Path to an abstract Unix domain socket */
  TOption(AbstractUnixSocket, CURLOPT_ABSTRACT_UNIX_SOCKET),

  /* Suppress proxy CONNECT response headers from user callbacks */
  TOption(SuppressConnectHeaders, CURLOPT_SUPPRESS_CONNECT_HEADERS),
};

#endif /* _shim_h_ */