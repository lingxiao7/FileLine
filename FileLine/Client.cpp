#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <WinSock2.h>
#include <iostream>
using namespace std;

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "WS2_32")
#pragma warning(disable:4996)

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "client.crt"
#define KEYF   HOME "client.key"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

DWORD WINAPI SendProc(LPVOID lpParameter);
DWORD WINAPI RecvProc(LPVOID lpParameter);

void socket_init_tcpip()
{
#ifdef _WIN32
	WORD     wVersionRequested;
	WSADATA  wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		return;
	}
	/* 检查版本号 */
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		return;
	}
#else	
#endif
}

void main()
{
	int err = 0;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;
	char*    str;
	char     buf[4096];
	SSL_METHOD *meth;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = (SSL_METHOD *)SSLv23_client_method();
	ctx = SSL_CTX_new(meth);    
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	CHK_NULL(ctx);
	CHK_SSL(err);

	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(3);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(4);
	}


	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */
	socket_init_tcpip();
	sd = socket(AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");   /* Server IP */
	sa.sin_port = htons(1111);          /* Server Port number */

	err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

	/* ----------------------------------------------- */
	/* Now we have TCP conncetion. Start SSL negotiation. */

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);
	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);
	CHK_SSL(err);

	/* Following two steps are optional and not required for
	data exchange to be successful. */

	/* Get the cipher - opt */

	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* Get server's certificate (note: beware of dynamic allocation) - opt */

	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	/* We could do all sorts of certificate verification stuff here before
	deallocating the certificate. */

	X509_free(server_cert);

	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	//CreateThread(NULL, 0, SendProc, &ssl, 0, NULL);
	//CreateThread(NULL, 0, RecvProc, &ssl, 0, NULL);

	while (1)
	{
		//发送消息  
		cout << "【客户端】:";
		scanf("%s", buf);
		err = SSL_write(ssl, buf, strlen(buf));
		CHK_SSL(err);

		//接收消息  
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		CHK_SSL(err);
		buf[err] = '\0';
		cout << "【服务器】:" << buf << endl;

	}

	SSL_shutdown(ssl);  /* send SSL/TLS close_notify */

	/* Clean up. */

	closesocket(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}


DWORD WINAPI SendProc(LPVOID lpParameter)
{
	int err = 0;
	char     buf[4096];
	SSL* ssl = (SSL*)lpParameter;
	while (1) {
		scanf("%s", buf);
		//发送消息  
		err = SSL_write(ssl, buf, strlen(buf));
		CHK_SSL(err);
		cout << "【客户端】:" << buf << endl;
	}
	return 0;
}


DWORD WINAPI RecvProc(LPVOID lpParameter)
{
	int err = 0;
	char     buf[4096];
	SSL* ssl = (SSL*)lpParameter;

	while (1) {
		//接收消息  
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		if (err <= 0) continue;
		CHK_SSL(err);
		buf[err] = '\0';
		cout << "【服务器】:" << buf << endl;
	}
	return 0;
}