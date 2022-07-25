#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <string>
#include<cstring>
#include <iostream>

using std::string;
using namespace std;
#include<stdio.h>
#include <openssl/rand.h>

#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>
#include <sstream>


#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <string>
#include <cstdlib>
#include <crypto++/cryptlib.h>
#include <crypto++/hex.h>
#include <crypto++/filters.h>
#include <crypto++/aes.h>
#include <crypto++/ccm.h>
#include "assert.h"
#include <crypto++/osrng.h>
#include <iostream>
#include "Eigen/Dense"
#include <random>
#include <ctime>
#include "sodium.h"
#include <cmath>


using namespace std;
using Eigen::Matrix;
using Eigen::MatrixXd;
using std::string;
using std::exit;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using std::cout;
using std::cerr;
using std::endl;


unsigned long data_size;

#define AESKeyLength 16
// defining the parameters
#define q 2000
// #define n 30
// #define m 270
#define n 30
#define m 270
#define e_min -1
#define e_max 1
#define PI 3.14
// define the number of bits in the bit stream
#define numberBits 128

#define rounds 1

// structures
// public key
struct publicKeyRegev
{
	Matrix<long, n, m> A;
	Matrix<long, 1, m> bT;
};

// private key
struct privateKeyRegev
{
	Matrix<long, n, m> A;
	Matrix<long, 1, n> sT;
};

// cipher text
struct cipherTextRegev
{
	Matrix<long, n, numberBits> u;
	Matrix<long, 1, numberBits> u_;    
};

struct AESPayload
{
	unsigned char* AESCipherText;
	cipherTextRegev AESKey;
	cipherTextRegev AESIv;
};

// modulus function
long mod(long value, long mod_value)
{
	return ((value % mod_value) + mod_value) % mod_value;
}

short * binConvert(unsigned char input[AESKeyLength]) 
{

  short*  bitstream = new short[AESKeyLength * 8];

  
  for (int i = 0; i < AESKeyLength; ++i)
   {
	for (int j = 0; j < 8; ++j) 
		{
		  bitstream[ (i*8 - j + 7)] = (input[i] >> j) & 1;    
		}
   } 
   
   return bitstream;
}

unsigned char* binToByteConvert(short bitstream[AESKeyLength]) 
{

  unsigned char*  bytestream = new unsigned char[AESKeyLength];

  short binValues[8] = {128, 64, 32, 16, 8, 4, 2, 1};
  short total = 0;
  short bytePosition = 0;   

  for (int i = 1; i < AESKeyLength * 8 + 1; ++i)
   {
		total = total + bitstream[i - 1] * binValues[(i - 1) % 8];

		if(i % 8 == 0)
		{
			bytestream[bytePosition] = (unsigned char)total;
			total = 0;
			bytePosition++;
		}
   }   

   return bytestream;
}

// genarate uniform random numbers including the boundaries
long genUniformRandomLong(int lowerBound, int upperBound)
{
	long range = (upperBound - lowerBound) + 1;
	uint32_t randomNumber;
	randomNumber = randombytes_uniform(range);
	long randomNumberModified = ((long)randomNumber) + lowerBound;
	return randomNumberModified;
}

long gaussian(double sigma){

	mt19937 gen(randombytes_random()); 
	normal_distribution<double> gauss_dis{0,sigma};
	double val = gauss_dis(gen);
	if (val > 0.5)
		val = val -1.0;
	else if(val<-0.5)
		val = val+1;
	return long(val*q); 

}

// function to genarate keys
void genarateRegevKeys(privateKeyRegev *private_key, publicKeyRegev *public_key)
{
	cout << "[LOG] Generating Matrix A" << endl;

	// Genarating the matrix A
	long number = 0;
	for (long i = 0; i < n; i++)
	{
		for (long j = 0; j < m; j++)
		{
			// filling the A matrix from the numbers taken from the distribution
			public_key->A(i, j) = genUniformRandomLong(0, q - 1);
		}
	}

	// avarage of A's coiff should be close to q/2
	// cout << "[DEBUG] Min of A : " << public_key->A.minCoeff() << " Max of A : " << public_key->A.maxCoeff() << endl;
	// cout << "[LOG] Done" << endl;

	// genarating the s matrix
	// cout << "[LOG] Generating Matrix s" << endl;
	for (long col = 0; col < private_key->sT.cols(); col++)
	{
		private_key->sT(col) = genUniformRandomLong(0, q - 1);
	}
	// cout << "[DEBUG] Min of s : " << private_key->sT.minCoeff() << " Max of s : " << private_key->sT.maxCoeff() << endl;
	// cout << "[LOG] Done" << endl;

	// genarating the error matrix
	// cout << "[LOG] Generating Matrix e" << endl;
	double alpha = sqrt(double(n))/q;
	double sigma = alpha/sqrt(2*PI);
	Matrix<long, 1, m> eT;
	// long total = 0;
	for (long col = 0; col < eT.cols(); col++)
	{
		// e should be small and should choosen between -7,7 (discreate gausisan distribution [ignore for now])
		eT(col) = gaussian(sigma);
		// total += eT(col);
	}
	// cout << "[DEBUG] min e: " << eT.minCoeff() << " max e: " << eT.maxCoeff() << " total :" << total << endl;

	// calculating bT
	public_key->bT = (private_key->sT) * (public_key->A) + eT;

	// taking the modulus values of bT
	for (long col = 0; col < public_key->bT.cols(); col++)
	{
		public_key->bT(col) = mod(public_key->bT(col), q);
	}

	// cout << "[DEBUG] Min of B : " << public_key->bT.minCoeff() << " Max of B : " << public_key->bT.maxCoeff() << endl;

	// sharig A among public and private key
	private_key->A = public_key->A;
}

// Encrypting Function
cipherTextRegev RegevEncrypt(publicKeyRegev public_key, short message_bit[numberBits])
{
	struct cipherTextRegev cipher_text;
	// Genarating the X matrix with random values
	Matrix<long, m, numberBits> X;
	for (long i = 0; i < m; i++)
	{
		for (long j = 0; j < numberBits; j++)
		{
			X(i, j) = genUniformRandomLong(0, 1);
		}
	}
	// cout<<"[DEBUG] min of X : "<<X.minCoeff()<<" max of X : "<<X.maxCoeff()<<endl;
	// u = AX
	// should take mod q
	cipher_text.u = (public_key.A) * X;
	// cout<<"[DEBUG] min of u : "<<cipher_text.u.minCoeff()<<" max of u : "<<cipher_text.u.maxCoeff()<<endl;
	// defining bTx
	Matrix<long, 1, numberBits> bTx;
	bTx = public_key.bT * X;
	// taking the modulus of bTx
	for (long i = 0; i < numberBits; i++)
	{
		bTx(0, i) = mod(bTx(0, i), q);
	}

	// encrypting the bits
	for (long i = 0; i < numberBits; i++)
	{
		cipher_text.u_(0, i) = mod((bTx(0, i) + (message_bit[i] * (q / 2))), q);
	}

	// cout<<"[DEBUG] u' : " <<cipher_text.u_ <<endl;
	return cipher_text;
}

// Decrypting Funciton
unsigned char *RegevDecrypt(privateKeyRegev private_key, cipherTextRegev cipher_text)
{
	// defining sTu
	Matrix<long, 1, numberBits> sTu;
	sTu = (private_key.sT) * (cipher_text.u);
	// array to hold the recoverd bits
	short*  recovered = new short[numberBits];
	long difference = 0;

	for (long i = 0; i < numberBits; i++)
	{
		sTu(0, i) = mod(sTu(0, i), q);
		// recovering the single bit message
		difference = mod(cipher_text.u_(0, i) - sTu(0, i), q);
		if ((difference > (q / 4)) & (difference < (3 * q / 4)))
		{ // bit is 1
			recovered[i] = 1;
		}
		else
		{
			recovered[i] = 0;
		}
	}

	return binToByteConvert(recovered);
}

// check the correctness
bool checkAnswer(unsigned char message[], unsigned char recovered[])
{
	int i = 0;
	while(message[i] != '\0')
	{

		if(message[i] != recovered[i])
		{
			//cout<<message[i]<<endl;
				return false;
		}
		i++;
	}

	return true;

}

// print an array of bits
void printBits(short bit_array[numberBits])
{
	for (long i = 0; i < numberBits; i++)
	{
		cout << bit_array[i];
	}
}

void printBlock(unsigned char array[], int length)
{
		for (int i = 0; i < length; ++i)
	{
		cout << (int)array[i] << endl;
	}

}

unsigned char* readFile(const char * filename)
{  
	unsigned char* data = new unsigned char[2000000];
	
	FILE *fp = fopen("1.txt","rb");
	int c;

	if(fp == NULL)
	{
		fprintf(stderr,"file input error.\n");
		return NULL;	
	} 
		

	for(data_size=0; data_size<2000000 && (c=fgetc(fp))!=EOF; data_size++) 
	{
		data[data_size] = c;
	}
	fclose(fp);
//cout << "read file: "<< data_size << endl;
	return data;
}

int writeFile(unsigned char out[], unsigned long out_size)
{
	FILE *fp = fopen("out.txt","wb");

	if(fp == NULL)
	{
		fprintf(stderr,"file output error.\n");
		return -1;	
	}
		
//cout << "write file: "<< out_size << endl;
	int i = 0;
	while(out[i] != '\0')
	{
		fputc(out[i], fp);
		i++;
	}
		
	fclose(fp);

	return 0;
}

unsigned char* encryptAES(AES_KEY enc_key, unsigned char key[], unsigned char iv[], const char * filename)
{	
	unsigned char* data = readFile(filename);
	//memset(iv, 0x01, AES_BLOCK_SIZE);
	/*
	cout << "key ######   enc" << endl;  
  printBlock(key, AES_BLOCK_SIZE);
  cout << " " << endl;

  cout << "iv ######   enc" << endl;  
  printBlock(iv, AES_BLOCK_SIZE);
  cout << " " << endl;
	*/


	unsigned long out_size = ((data_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	unsigned char* encrypted = new unsigned char[out_size];

	for(int i=data_size; i<out_size; i++) 
		data[i] = (out_size-data_size);
    AES_set_encrypt_key(key, 128, &enc_key); // 128bit = 16byte
    AES_cbc_encrypt(data, encrypted,out_size, &enc_key, iv, AES_ENCRYPT);
/*
      cout << "iv ### aftere enc" << endl;
  printBlock(iv, AES_BLOCK_SIZE);
  cout << " " << endl;
*/
    return encrypted;
}


unsigned char* decryptAES(AES_KEY enc_key, unsigned char encrypted[], unsigned char key[], unsigned char iv[])
{	
/*
	cout << "key ######   dec" << endl;  
  printBlock(key, AES_BLOCK_SIZE);
  cout << " " << endl;

  cout << "iv ######   dec" << endl;  
  printBlock(iv, AES_BLOCK_SIZE);
  cout << " " << endl;
*/
	//unsigned long data_size = sizeof(encrypted)/sizeof(encrypted[0]); // resolve here
	unsigned char* decrypted = new unsigned char[data_size];
  AES_set_decrypt_key(key, 128, &enc_key);
  //memset(iv, 0x01, AES_BLOCK_SIZE);
  AES_cbc_encrypt(encrypted, decrypted, data_size, &enc_key, iv, AES_DECRYPT);
  
  unsigned char tail = decrypted[data_size-1];

   
   int valid = (tail > 0 && tail<=AES_BLOCK_SIZE) ;

  	
  	for(int i=1;i<tail && valid;i++)
		valid = (decrypted[data_size-1-i] == tail);
	  writeFile(decrypted, data_size);
 	/*
 	if(!valid) 
 	{
 		fprintf(stderr,"padding error.\n");
 		return NULL;
 	} 
  
  data_size -= tail;

  cout << "no issue in decryptAES" << endl;
  writeFile(decrypted, data_size);
	*/
	//writeFile(decrypted, data_size);
  return decrypted;
}




int main(int argc, char* argv[])
{
	struct AESPayload AES;
	unsigned char* data = readFile(argv[0]);

  	// genarating regev system keys
	struct privateKeyRegev private_key;
	struct publicKeyRegev public_key;
	genarateRegevKeys(&private_key, &public_key);

	double success = 0;

   for (int i = 0; i < rounds; ++i)
   {
   	AES_KEY aesKey, aesKey2;
   	unsigned char iv[16];
  	unsigned char key[16];
   	unsigned char receiverIV[16];
 		unsigned char receiverKey[16];
   	RAND_bytes(iv, 16);
  	RAND_bytes(key, 16);
  	short *binKey = binConvert(key);
	  short *binIV = binConvert(iv);

	  AES.AESKey = RegevEncrypt(public_key, binKey);
		AES.AESIv = RegevEncrypt(public_key, binIV);

   	AES.AESCipherText = encryptAES(aesKey, key, iv, argv[0]);


		//cout<<"AES payload ok"<<endl;

		unsigned char *recovered_AESKey = RegevDecrypt(private_key, AES.AESKey);
		unsigned char *recovered_AESIv = RegevDecrypt(private_key, AES.AESIv);
		//cout<<"AES recovery ok"<<endl;
		//string recovered = AESDecrypt(recovered_AESKey, recovered_AESIv, AES.AESCipherText);
		unsigned char* decrypted = decryptAES(aesKey2, AES.AESCipherText, recovered_AESKey, recovered_AESIv);
		//cout<<"AES decrypted ok"<<endl;
		//delete[] binKey; delete[] binIV;
		//cout<<i<<": "<<endl;
		
		if (checkAnswer(data, decrypted))
        {
            success++;
            //cout<<" good"<<endl;
        }
        //else
        	//cout<<"bad"<<endl;
        delete[] recovered_AESKey; delete[] recovered_AESIv; delete[] binKey; delete[] binIV; 
   }

   cout << "Encryption and Decryption works " << (success / rounds) * 100 << "% of time." << endl;

/*
  cout << "key ######################################" << endl;
  printBlock(key, AES_BLOCK_SIZE);
  cout << " " << endl;


  cout << "iv ######################################" << endl;
  printBlock(iv, AES_BLOCK_SIZE);
  cout << " " << endl;



	

	for (int i = 0; i < data_size; ++i)
	{
		if(data[i] != decrypted[i])
		{
			cout << "data["<<i<<"] : "<< (int)data[i]<<"	#		decrypted["<<i<<"] : "<< (int)decrypted[i] << endl;
		}
	}
	*/
     return 0;
}