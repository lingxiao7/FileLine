#pragma once
#include <iostream>    
#include <cassert>  
#include <string>    
#include <vector>    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/des.h> 
#include <openssl/err.h>
#include <WinSock2.h>

#define BUFFSIZE 4096
#define BUFFER_SIZE 4096
#define PORT 8087
#define SERVER_IP "127.0.0.1"
#define FILE_NAME_MAX_SIZE 512
#pragma comment(lib, "WS2_32")
#pragma warning(disable:4996)

void generateRSAKey(std::string Key[2]);
RSA* getRSAKey(std::string fileKey);
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey);
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey);

std::string rsa_pri_encrypt(const std::string &clearText, const std::string &priKey);
std::string rsa_pub_decrypt(const std::string &cipherText, const std::string &pubKey);

std::string des_decrypt(const std::string &cipherText, const std::string &key);
std::string des_encrypt(const std::string &clearText, const std::string &key);

BOOL md5(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr);

BOOL receiveFile(SOCKET & socket, char * file_name, const char * desKey = NULL);
BOOL sendFile(SOCKET & socket, char * file_name, const char * desKey = NULL);