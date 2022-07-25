#include <iostream>
#include<stdio.h>
#include <string.h>
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


using std::string;
using namespace std;
using Eigen::Matrix;
using Eigen::MatrixXd;

#define numberBits 128
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

long gaussian(double sigma);
long mod(long value, long mod_value);
unsigned char* binToByteConvert(short bitstream[AESKeyLength]);
short * binConvert(unsigned char input[AESKeyLength]);
long genUniformRandomLong(int lowerBound, int upperBound);
long genUniformRandomLong(int lowerBound, int upperBound);
void genarateRegevKeys(privateKeyRegev *private_key, publicKeyRegev *public_key);
cipherTextRegev RegevEncrypt(publicKeyRegev public_key, short message_bit[numberBits]);
unsigned char *RegevDecrypt(privateKeyRegev private_key, cipherTextRegev cipher_text);