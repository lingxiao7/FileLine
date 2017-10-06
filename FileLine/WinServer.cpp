/*
 File name: WinServer.cpp
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
#pragma comment(lib, "WS2_32")
#pragma warning(disable:4996)

int main() {
	// Init Server addr.
	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);

	// Init Socket dll
	WSADATA wsaData;
	WORD socketVersion = MAKEWORD(2, 0);
	if (0 != WSAStartup(socketVersion, &wsaData)) {
		printf("Init socket dll error!\n");
		exit(1);
	}

	// Create Socket
	SOCKET m_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == m_socket) {
		printf("Create Sochet Error!\n");
		exit(1);
	}

	// Bind Socket and Server addr
	if (SOCKET_ERROR == bind(m_socket, (LPSOCKADDR)&server_addr, sizeof(server_addr))) {
		printf("Server Bind Failed: %d.\n", WSAGetLastError());
		exit(1);
	}

	// Listening
	if (SOCKET_ERROR == listen(m_socket, 10)) {
		printf("Server Listen Failed: %d", WSAGetLastError());
		exit(1);
	}

	while (1) {
		printf("Listening To Client...\n");

		sockaddr_in client_addr;
		int client_addr_len = sizeof(client_addr);
		SOCKET m_New_Socket = accept(m_socket, (sockaddr *)&client_addr, &client_addr_len);
		if (SOCKET_ERROR == m_New_Socket) {
			printf("Server Accept Failed: %d.\n", WSAGetLastError());
			break;
		}

		char buffer[BUFFER_SIZE + 1];
		memset(buffer, 0, BUFFER_SIZE + 1);
		if (recv(m_New_Socket, buffer, BUFFER_SIZE, 0) < 0) {
			printf("Server Receive Data Failed!");
			break;
		}

		char file_name[FILE_NAME_MAX_SIZE + 1];
		memset(file_name, 0, FILE_NAME_MAX_SIZE + 1);
		strncpy(file_name, buffer, strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));
		printf("%s\n", file_name);

		FILE *fp = fopen(file_name, "rb");

		if (NULL == fp) {
			printf("File: %s Not Found.\n", file_name);
		} else {
			memset(buffer, 0, BUFFER_SIZE);
			int length = 0;
			while ((length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) > 0) {
				if (send(m_New_Socket, buffer, length, 0) < 0) {
					printf("Send File: %s Failed.\n", file_name);
					break;
				}
				memset(buffer, 0, BUFFER_SIZE);
			}

			fclose(fp);
			printf("File: %s Transfer Successful!\n", file_name);
		}
		closesocket(m_New_Socket);
	}
	closesocket(m_socket);
	WSACleanup();
	return 0;
}