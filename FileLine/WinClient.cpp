/*
File name: ClientServer.cpp
Author:    Chengxiang
E-mail:    lingxiao007a@gmail.com
Date:	    2017.10.2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>

#define PORT 8087
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024
#define FILE_NAME_MAX_SIZE 512
// #pragma comment(lib, "WS2_32")
// #pragma warning(disable:4996)

int main() {
	// Init Server addr.
	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	server_addr.sin_port = htons(PORT);

	// Init Socket dll
	WSADATA wsaData;
	WORD socketVersion = MAKEWORD(2, 0);
	if (0 != WSAStartup(socketVersion, &wsaData)) {
		printf("Init socket dll error!\n");
		exit(1);
	}

	// Create Socket
	SOCKET c_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == c_socket) {
		printf("Create Sochet Error!\n");
		exit(1);
	}

	if (SOCKET_ERROR == connect(c_socket, (LPSOCKADDR)&server_addr, sizeof(server_addr))) {
		printf("Can Not Connect To Server IP!\n");
		system("pause");
		exit(1);
	}

	char file_name[FILE_NAME_MAX_SIZE + 1];
	memset(file_name, 0, FILE_NAME_MAX_SIZE + 1);
	printf("Please input your File name on server: ");
	scanf("%s", &file_name);

	char buffer[BUFFER_SIZE + 1];
	memset(buffer, 0, BUFFER_SIZE + 1);
	strncpy(buffer, file_name, strlen(file_name)>BUFFER_SIZE ? BUFFER_SIZE : strlen(file_name));

	if (send(c_socket, buffer, BUFFER_SIZE, 0) < 0) {
		printf("Send File Name Failed.\n");
		system("pause");
		exit(1);
	}

	FILE *fp = fopen(file_name, "wb");
	if (NULL == fp) {
		printf("File: %s Can Not Open to Write.\n", file_name);
		system("pause");
		exit(1);
	} else {
		memset(buffer, 0, BUFFER_SIZE);
		int length = 0;
		while ((length = recv(c_socket, buffer, BUFFER_SIZE, 0)) > 0) {
			if (fwrite(buffer, sizeof(char), length, fp) > length) {
				printf("File: %s Write Failed.\n", file_name);
				break;
			}
			memset(buffer, 0, BUFFER_SIZE);
		}
		
		printf("Receive File: %s From Successful!\n", file_name);
	}
	fclose(fp);
	closesocket(c_socket);

	WSACleanup();
	system("pause");
	return 0;
}