#include <crypto++/aes.h>
#include <crypto++/modes.h>
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

#include <random>
#include <ctime>
#include "sodium.h"
#include <cmath>

using namespace std;

using std::string;
using std::exit;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using std::cout;
using std::cerr;
using std::endl;
using CryptoPP::CTR_Mode;
using CryptoPP::AES;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Exception;
using CryptoPP::AutoSeededRandomPool;

byte* generateAESKey(short length)
{	
	byte* key  = new byte[length];
	AutoSeededRandomPool rnd;
	rnd.GenerateBlock(key, length);
	//rnd.GenerateBlock(iv, 32);  

	return key;  
}

int main(int argc, char* argv[])
{

	short length = 32;



	byte* key = generateAESKey(length);


	for (short i = 0; i < length; ++i)
	{
		cout<<i << " " << (int)key[i]  << endl;
	}


	return 0;
}

