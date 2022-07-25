
using namespace std;
#include<stdio.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "Regev.h"
#include "FileHandle.h"


struct AESPayload
{
	unsigned char* AESCipherText;
	cipherTextRegev AESKey;
	cipherTextRegev AESIv;
};

unsigned char* encryptAES(AES_KEY enc_key, unsigned char key[], unsigned char iv[], const char * filename);
unsigned char* decryptAES(AES_KEY enc_key, unsigned char key[], unsigned char iv[], const char * OutputFilename);
bool checkAnswer(unsigned char message[], unsigned char recovered[]);