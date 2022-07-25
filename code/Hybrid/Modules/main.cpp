
#include "AES.h"


int main(int argc, char const *argv[])
{
	//struct InputFile input = readFile("1.txt");

	unsigned char key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
    unsigned char iv[16]  = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
    AES_KEY enc_key;

    encryptAES( enc_key,  key,  iv, "1.txt");

	



	return 0;
}