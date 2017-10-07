#include "WinCrypto.h"

// ---- rsa非对称加解密 ---- //    
#define KEY_LENGTH  2048              // 密钥长度  
#define PUB_KEY_FILE_NEW "pubKey.pem"    // 公钥路径  
#define PRI_KEY_FILE_NEW "priKey.pem"    // 私钥路径  

// 函数方法生成密钥对   
void generateRSAKey(std::string strKey[2])
{
	// 公私密钥对    
	size_t pri_len;
	size_t pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	// 生成密钥对    
	RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	// 获取长度    
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串    
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// 存储密钥对    
	strKey[0] = pub_key;
	strKey[1] = pri_key;

	// 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）  
	FILE *pubFile = fopen(PUB_KEY_FILE_NEW, "w");
	if (pubFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile = fopen(PRI_KEY_FILE_NEW, "w");
	if (priFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pri_key, priFile);
	fclose(priFile);

	// 内存释放  
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
}


RSA* getRSAKey(std::string fileKey) {
	std::string strRet;
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)fileKey.c_str(), -1);
	// 此处有三种方法  
	// 1, 读取内存里生成的密钥对，再从内存生成rsa  
	// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
	// 3，直接从读取文件指针生成rsa  
	RSA* pRSAPublicKey = RSA_new();
	rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	return rsa;
}

// 命令行方法生成公私钥对（begin public key/ begin private key）  
// 找到openssl命令行工具，运行以下  
// openssl genrsa -out prikey.pem 1024   
// openssl rsa - in privkey.pem - pubout - out pubkey.pem  

// 公钥加密    
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey)
{
	std::string strRet;
	RSA *rsa = NULL;
	BIO  *keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, pubKey.c_str());
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);

	int len = RSA_size(rsa);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	// 加密函数  
	int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	// 释放内存  
	//free(encryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

// 私钥解密    
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey)
{
	std::string strRet;
	RSA *rsa = NULL;
	BIO  *keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, priKey.c_str());
	rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);

	int len = RSA_size(rsa);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// 解密函数  
	int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	// 释放内存  
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}


std::string rsa_pri_encrypt(const std::string &clearText, const std::string &priKey) {

	std::string strRet;
	RSA *rsa = NULL;
	BIO  *keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, priKey.c_str());
	rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);

	int len = RSA_size(rsa);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);


	// 加密函数  
	int ret = RSA_private_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	// 释放内存  
	free(encryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

std::string rsa_pub_decrypt(const std::string &cipherText, const std::string &pubKey) {
	std::string strRet;
	RSA *rsa = NULL;
	BIO  *keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, pubKey.c_str());
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
	int len = RSA_size(rsa);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// 解密函数  
	int ret = RSA_public_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	// 释放内存  
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

// ---- md5摘要哈希 ---- //    
BOOL md5(const std::string & file_name, std::string &encodedStr, std::string &encodedHexStr)
{
	MD5_CTX ctx;
	int len = 0;
	unsigned char buffer[1024] = { 0 };
	unsigned char digest[16] = { 0 };

	FILE *fp = fopen(file_name.c_str(), "rb");
	if (NULL == fp) {
		printf("ERROR: File: %s Can Not Open to Write.\n", file_name.c_str());
		return false;
	}

	MD5_Init(&ctx);

	while ((len = fread(buffer, 1, 1024, fp)) > 0)
	{
		MD5_Update(&ctx, buffer, len);
	}

	MD5_Final(digest, &ctx);

	fclose(fp);

	encodedStr = encodedHexStr = "";
	char tmp[3] = { 0 };
	for (int i = 0; i < 16; i++)
	{
		sprintf(tmp, "%02X", digest[i]); // sprintf并不安全  
		encodedHexStr += tmp;
		encodedStr += digest[i];
	}
	return true;
}

// ---- des对称加解密 ---- //    
// 加密 ecb模式    
std::string des_encrypt(const std::string &clearText, const std::string &key)
{
	std::string cipherText; // 密文    

	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	// 构造补齐后的密钥    
	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	// 密钥置换    
	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	// 循环加密，每8字节一次    
	const_DES_cblock inputText;
	DES_cblock outputText;
	std::vector<unsigned char> vecCiphertext;
	unsigned char tmp[8];

	for (int i = 0; i < clearText.length() / 8; i++)
	{
		memcpy(inputText, clearText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCiphertext.push_back(tmp[j]);
	}

	if (clearText.length() % 8 != 0)
	{
		int tmp1 = clearText.length() / 8 * 8;
		int tmp2 = clearText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, clearText.c_str() + tmp1, tmp2);
		// 加密函数    
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCiphertext.push_back(tmp[j]);
	}

	cipherText.clear();
	cipherText.assign(vecCiphertext.begin(), vecCiphertext.end());

	return cipherText;
}

// 解密 ecb模式    
std::string des_decrypt(const std::string &cipherText, const std::string &key)
{
	std::string clearText; // 明文    

	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	const_DES_cblock inputText;
	DES_cblock outputText;
	std::vector<unsigned char> vecCleartext;
	unsigned char tmp[8];

	for (int i = 0; i < cipherText.length() / 8; i++)
	{
		memcpy(inputText, cipherText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCleartext.push_back(tmp[j]);
	}

	if (cipherText.length() % 8 != 0)
	{
		int tmp1 = cipherText.length() / 8 * 8;
		int tmp2 = cipherText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, cipherText.c_str() + tmp1, tmp2);
		// 解密函数    
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCleartext.push_back(tmp[j]);
	}

	clearText.clear();
	clearText.assign(vecCleartext.begin(), vecCleartext.end());

	return clearText;
}

BOOL receiveFile(SOCKET & socket, char * file_name, const char * desKey) {
	char buffer[BUFFER_SIZE + 1];
	char file_nameE[FILE_NAME_MAX_SIZE + 1] = "E";
	strcat(file_nameE, file_name);

	FILE *fp = fopen(file_name, "wb");
	unsigned long long file_size = 0;
	int length = 0;
	recv(socket, (char*)&file_size, sizeof(unsigned long long) + 1, NULL);
	// printf("Get File Size: %d.\n", file_size);

	if (NULL != desKey) {
		fclose(fp);
		fp = fopen(file_nameE, "wb");
	}

	if (NULL == fp) {
		printf("ERROR: File %s Can Not Open to Write.\n", file_name);
		return false;
	}
	else {
		memset(buffer, 0, BUFFER_SIZE);
		DWORD dwNumberOfBytesRecv = 0;
		unsigned long long fs = file_size;
		do
		{
			int bufSize = BUFFER_SIZE;
			if (fs < bufSize) bufSize = fs;
			dwNumberOfBytesRecv = recv(socket, buffer, bufSize, 0);
			fwrite(buffer, sizeof(char), dwNumberOfBytesRecv, fp);
			if (fs == dwNumberOfBytesRecv) file_size = dwNumberOfBytesRecv;
		} while (file_size -= dwNumberOfBytesRecv);
	}
	fclose(fp);

	if (NULL != desKey) {
		FILE *fp = fopen(file_name, "wb");
		FILE *fep = fopen(file_nameE, "rb");
		length = 0;
		memset(buffer, 0, BUFFER_SIZE);
		while (length = fread(buffer, sizeof(char), BUFFER_SIZE, fep)) {
			std::string s_tmp = des_decrypt(buffer, desKey);
			if (file_size == length) s_tmp[file_size] = 0;
			fwrite(s_tmp.c_str(), sizeof(char), length, fp);

			memset(buffer, 0, BUFFER_SIZE);
		}
		fclose(fp);
		fclose(fep);
	}

	return true;
}

BOOL sendFile(SOCKET & socket, char * file_name, const char * desKey) {
	char buffer[BUFFER_SIZE + 1];
	char file_nameE[FILE_NAME_MAX_SIZE + 1] = "E";
	strcat(file_nameE, file_name);
	unsigned long long file_size = 0;
	FILE *fp = fopen(file_name, "rb");
	FILE *fep;
	int length = 0;

	// Encrypt FILE
	if (NULL != desKey) {
		fep = fopen(file_nameE, "wb");
		memset(buffer, 0, BUFFER_SIZE);
		while (length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) {
			if (length <= 0) break;
			std::string s_tmp = des_encrypt(buffer, desKey);
			if (fwrite(s_tmp.c_str(), sizeof(char), length, fep) > length) {
				printf("ERROR: File: %s Write Failed.\n", file_nameE);
				break;
			}
			memset(buffer, 0, BUFFER_SIZE);
		}
		fclose(fep);
		fclose(fp);

		fp = fopen(file_nameE, "rb");
	}

	// Get size of file
	fseek(fp, 0, 2);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Send size of file
	send(socket, (char*)&file_size, sizeof(unsigned long long) + 1, NULL);
	// printf("Size: %d.\n", file_size);

	// Send File
	if (NULL == fp) {
		printf("ERROR: File %s Not Found.\n", file_name);
	}
	else {
		memset(buffer, 0, BUFFER_SIZE);
		length = 0;
		while (length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) {
			if (length <= 0) break;
			if (send(socket, buffer, length, 0) < 0) {
				printf("ERROR: Send File %s Failed.\n", file_name);
				break;
			}
			memset(buffer, 0, BUFFER_SIZE);
		}

		//printf("OK: File %s Transfer Successful!\n", file_name);
	}
	fclose(fp);

	return true;
}