#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <WinSock2.h>
#include <iostream>
using namespace std;


#include <openssl/rsa.h>       /* SSLeay stuff */
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
#define CERTF  HOME "server.crt"
#define KEYF   HOME "server.key"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

DWORD WINAPI RecvProc(LPVOID lpParameter);
DWORD WINAPI SendProc(LPVOID lpParameter);

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
SSL*     ssl;

int main()
{
	int err = 0;
	int listen_sd;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	SSL_CTX* ctx;
	X509*    client_cert;
	char*    str;
	char     buf[4096];
	SSL_METHOD *meth;

	/* SSL preliminaries. We keep the certificate and key with the context. */

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = (SSL_METHOD *)SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	CHK_NULL(ctx);
	CHK_SSL(err);


	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

	/* ----------------------------------------------- */
	/* Prepare TCP socket for receiving connections */
	socket_init_tcpip();
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(1111);          /* Server Port number */

	err = bind(listen_sd, (struct sockaddr*) &sa_serv,
		sizeof(sa_serv));                   
	CHK_ERR(err, "bind");

	/* Receive a TCP connection. */

	err = listen(listen_sd, 5);                    
	CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept(listen_sd, (struct sockaddr*) &sa_cli, (int*)&client_len);
	CHK_ERR(sd, "accept");
	closesocket(listen_sd);

	printf("Connection from %lx, port %x\n",
		sa_cli.sin_addr.s_addr, sa_cli.sin_port);

	/* ----------------------------------------------- */
	/* TCP connection is ready. Do server side SSL. */

	ssl = SSL_new(ctx);   
	CHK_NULL(ssl);
	SSL_set_fd(ssl, sd);
	err = SSL_accept(ssl);
	CHK_SSL(err);

	/* Get the cipher - opt */

	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* Get client's certificate (note: beware of dynamic allocation) - opt */

	client_cert = SSL_get_peer_certificate(ssl);
	//CHK_NULL(client_cert);
	if (client_cert != NULL) {
		printf("Client certificate:\n");

		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t subject: %s\n", str);
		OPENSSL_free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t issuer: %s\n", str);
		OPENSSL_free(str);

		/* We could do all sorts of certificate verification stuff here before
		deallocating the certificate. */

		X509_free(client_cert);
	}
	else
		printf("Client does not have certificate.\n");

	/* DATA EXCHANGE - Receive message and send reply. */

	//CreateThread(NULL, 0, SendProc, NULL, 0, NULL);
	CreateThread(NULL, 0, RecvProc, NULL, 0, NULL);

	while (true)
	{
		////接收消息  
		//err = SSL_read(ssl, buf, sizeof(buf) - 1);
		//CHK_SSL(err);
		//buf[err] = '\0';
		//cout << "【客户端】:" << buf << endl;

		//发送消息  
		scanf("%s", buf);
		err = SSL_write(ssl, buf, strlen(buf));
		CHK_SSL(err);
		cout << "【服务器】:" << buf << endl;
	}

	/* Clean up. */

	closesocket(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}


DWORD WINAPI RecvProc(LPVOID lpParameter)
{
	int err = 0;
	char     buf[4096];
	//SSL* ssl = (SSL*)lpParameter;

	while (1) {
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		//if (err <= 0) continue;
		CHK_SSL(err);
		buf[err] = '\0';
		cout << "【客户端】:" << buf << endl;
	}
	return 0;
}


DWORD WINAPI SendProc(LPVOID  lpParameter)
{
	int err = 0;
	char     buf[4096];
	//SSL* ssl = (SSL*)lpParameter;
	while (1) {
		cin >> buf;
		//发送消息  
		err = SSL_write(ssl, buf, strlen(buf));
		CHK_SSL(err);
		cout << "【服务器】:" << buf << endl;
	}
	return 0;
}