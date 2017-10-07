/*
File name: ClientServer.cpp
Author:    Chengxiang
E-mail:    lingxiao007a@gmail.com
Date:	    2017.10.2
*/
#include "WinCrypto.h"

#define PUB_KEY_FILE "pubKeyB.pem"    // ¹«Ô¿Â·¾¶  
#define PRI_KEY_FILE "priKeyB.pem"    // Ë½Ô¿Â·¾¶ 
#define PUB_KEY_FILE_R "pubKeyA.pem"    // ¹«Ô¿Â·¾¶  
#define PRI_KEY_FILE_R "priKeyA.pem"    // Ë½Ô¿Â·¾¶ 
#pragma comment(lib, "WS2_32")
#pragma warning(disable:4996)

sockaddr_in server_addr;
SOCKET c_socket;
WSADATA wsaData;

void connectUp() {
	// Init Server addr.
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	server_addr.sin_port = htons(PORT);

	// Init Socket dll
	WORD socketVersion = MAKEWORD(2, 0);
	if (0 != WSAStartup(socketVersion, &wsaData)) {
		printf("Init socket dll error!\n");
		exit(1);
	}

	// Create Socket
	c_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == c_socket) {
		printf("Create Sochet Error!\n");
		exit(1);
	}

	if (SOCKET_ERROR == connect(c_socket, (LPSOCKADDR)&server_addr, sizeof(server_addr))) {
		printf("Can Not Connect To Server IP!\n");
		system("pause");
		exit(1);
	}
}

void connectDown() {
	closesocket(c_socket);
	WSACleanup();
}

int main() {
	connectUp();

	char buffer[BUFFER_SIZE + 1];
	char file_name[FILE_NAME_MAX_SIZE + 1] = PUB_KEY_FILE;
	char file_nameRece[FILE_NAME_MAX_SIZE + 1] = PUB_KEY_FILE_R;


	// Send PubKey
	strcpy(file_name, PUB_KEY_FILE);
	if (0 == sendFile(c_socket, file_name)) {
		puts("ERROR: Send Public Key Failed.");
		exit(1);
	}
	printf("OK(1): Send File (%s) Successful!\n", PUB_KEY_FILE);

	// Receive PubKey
	// Get File Name
	if (0 == receiveFile(c_socket, file_nameRece)) {
		puts("ERROR: Receive Public Key Failed.");
		exit(1);
	}
	printf("OK(2): Receive File (%s) Successful!\n", file_nameRece);
	
	while (1) {
		// Send File Name
		printf("Please input the file you want get from Server: ");
		char file_nameG[FILE_NAME_MAX_SIZE + 1] = "1.txt";
		scanf("%s", file_nameG);
		if (send(c_socket, file_nameG, strlen(file_nameG), NULL) < 0) {
			printf("ERROR: Send filename Failed.\n", file_nameG);
			exit(1);
		}
		printf("OK(3): Send File name %s Successful!\n", file_nameG);

		// Receive DES KEY
		char s_desKey[512];
		memset(buffer, 0, BUFFER_SIZE + 1);
		if (recv(c_socket, buffer, BUFFER_SIZE, 0) < 0) {
			printf("ERROR: Receive Data Failed!");
			return false;
		}
		strcpy(s_desKey, rsa_pri_decrypt((std::string)buffer, PRI_KEY_FILE).c_str());
		printf("OK(4): Now, I get DES KEY.%s \n", s_desKey);

		// Receive File, then Decrypt
		FILE *fp = fopen(file_nameG, "wb");
		if (NULL == fp) {
			printf("ERROR: File: %s Can Not Open to Write.\n", file_nameG);
			exit(1);
		}
		else {
			receiveFile(c_socket, file_nameG, s_desKey);
			printf("OK(5): Receive File: %s Successful!\n", file_nameG);
		}
		fclose(fp);

		// Sum MD5 and Check
		char encodedHexStr[512];
		std::string s_encodedStr, s_encodedHexStr;
		char file_nameE[FILE_NAME_MAX_SIZE] = "E";
		strcat(file_nameE, file_nameG);
		md5(file_nameE, s_encodedStr, s_encodedHexStr);
		memset(buffer, 0, BUFFER_SIZE + 1);
		if (recv(c_socket, buffer, BUFFER_SIZE, 0) < 0) {
			printf("ERROR: Receive Data Failed!");
			return false;
		}

		// Decrypt MD5
		std::string  MD5 = rsa_pub_decrypt(buffer, PUB_KEY_FILE_R);
		printf("OK(6): Receive MD5 Successful!\n");
		if (s_encodedHexStr.c_str() == MD5) {
			printf("OK(7): MD5 Checked. %s.\n", MD5.c_str());
			char s_y[] = "YES";
			if (send(c_socket, s_y, strlen(s_y), 0) < 0) {
				printf("ERROR: Send CHECK Failed.\n", s_y);
				exit(1);
			}
		} else {
			puts("MD5 failed.");
			char s_n[] = "NO";
			if (send(c_socket, s_n, strlen(s_n), 0) < 0) {
				printf("ERROR: Send CHECK Failed.\n", s_n);
				exit(1);
			}
		}
	}
	
	connectDown();
	return 0;
}