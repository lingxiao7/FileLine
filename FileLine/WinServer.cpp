/*
 File name: WinServer.cpp
 Author:    Chengxiang
 E-mail:    lingxiao007a@gmail.com
 Date:	    2017.10.2
*/

#include "WinCrypto.h"

#define PUB_KEY_FILE "pubKeyA.pem"    // ¹«Ô¿Â·¾¶  
#define PRI_KEY_FILE "priKeyA.pem"    // Ë½Ô¿Â·¾¶
#define PUB_KEY_FILE_R "pubKeyB.pem"    // ¹«Ô¿Â·¾¶  
#define PRI_KEY_FILE_R "priKeyB.pem"    // Ë½Ô¿Â·¾¶

sockaddr_in server_addr;
WSADATA wsaData;
SOCKET m_socket;

sockaddr_in client_addr;
int client_addr_len;
SOCKET m_New_Socket;

void connectUp() {
	// Init Server addr.
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);

	// Init Socket dll
	WORD socketVersion = MAKEWORD(2, 0);
	if (0 != WSAStartup(socketVersion, &wsaData)) {
		printf("Init socket dll error!\n");
		exit(1);
	}

	// Create Socket
	m_socket = socket(AF_INET, SOCK_STREAM, 0);
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
}

void connectDown() {
	closesocket(m_socket);
	WSACleanup();
}

int main() {
	char buffer[BUFFER_SIZE + 1];
	char file_name[FILE_NAME_MAX_SIZE + 1] = PUB_KEY_FILE;
	char file_nameRece[FILE_NAME_MAX_SIZE + 1];
	connectUp();

	while (1) {
		while (1) {
			// Listening ...
			printf("Listening To Client...\n");
			client_addr_len = sizeof(client_addr);
			m_New_Socket = accept(m_socket, (sockaddr *)&client_addr, &client_addr_len);
			if (SOCKET_ERROR == m_New_Socket) {
				printf("ERROR: Server Accept Failed: %d.\n", WSAGetLastError());
				return false;
			}
			printf("OK(1): Connect from Client.\n");

			// Receive Public Key From Client
			if (0 == receiveFile(m_New_Socket, PUB_KEY_FILE_R)) {
				exit(1);
			}
			printf("OK(2): Receive File (%s) Successful!\n", PUB_KEY_FILE_R);

			// Send Public Key TO Client
			if (0 == sendFile(m_New_Socket, PUB_KEY_FILE)) {
				exit(1);
			}
			printf("OK(3): Send File (%s) Successful!\n", PUB_KEY_FILE);

			// Generate DES Key and Encrypt, then Send.
			DES_cblock desKey;
			const char s_desKey[] = "this is my key";
			DES_string_to_key(s_desKey, &desKey);

			std::string s_eDesKey = rsa_pub_encrypt(s_desKey, PUB_KEY_FILE_R);
			printf("OK(4): Encrypt des Key Successful!\n");

			if (send(m_New_Socket, s_eDesKey.c_str(), s_eDesKey.length(), 0) < 0) {
				printf("ERROR: Send des KEY Failed.\n");
				break; 
			}
			printf("OK(5): Send des Key Successful!\n");

			// Get File Name which will be sent
			// Encrypt File and Send 
			memset(buffer, 0, BUFFER_SIZE + 1);
			if (recv(m_New_Socket, buffer, BUFFER_SIZE, 0) < 0) {
				printf("ERROR: Receive Data Failed!");
				return false;
			}
			strcpy(file_nameRece, buffer);
			char file_nameE[FILE_NAME_MAX_SIZE + 1] = "E";
			printf("OK(6): Receive File name (%s) Successful!\n", file_nameRece);
			strcat(file_nameE, file_nameRece);
			FILE * fp = fopen(file_nameRece, "rb");
			if (NULL == fp) {
				printf("ERROR: File: %s Can Not Open to Read.\n", file_nameRece);
				exit(1);
			}
			else {
				sendFile(m_New_Socket, file_nameRece, s_desKey);
				printf("OK(7): Encrypt File %s Successful!\n", file_nameRece);
				printf("OK(8): Send File %s Successful!\n", file_nameE);
			}
			fclose(fp);

			// Cal MD5, then send
			std::string encodedHexStr, encodedStr;
			md5(file_nameE, encodedStr, encodedHexStr);
			std::string  encodedMD5 = rsa_pri_encrypt(encodedHexStr, PRI_KEY_FILE);
			printf("OK(9): Cal MD5 Successful!\n");
			if (send(m_New_Socket, encodedMD5.c_str(), encodedMD5.length(), 0) < 0) {
				printf("ERROR: Send MD5 Failed.\n");
				exit(1);
			}
			printf("OK(10): Send MD5 Successful!\n");


			// Check Yes or No
			char s_check[BUFFER_SIZE + 1];
			memset(buffer, 0, BUFFER_SIZE + 1);
			if (recv(m_New_Socket, buffer, BUFFER_SIZE, 0) < 0) {
				printf("ERROR: Receive Data Failed!");
				return false;
			} else {
				printf("OK(11): GET YES Successful!\n");
			}
			if (strcmp(buffer, "YES") == 0) break;
		}
		

		// Close newSocket
		closesocket(m_New_Socket);
	}

	connectDown();
	return 0;
}