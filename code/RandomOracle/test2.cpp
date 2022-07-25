#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdio.h>
#include <string.h>
#include <crypto++/hex.h>
#include <crypto++/sha.h>
#include <crypto++/files.h>
// #include <crypto++/cryptlib.h>
// #include <crypto++/filters.h>
// #include <crypto++/osrng.h>
// using namespace std;

// compile g++ ___.cpp -lcrypto++

using namespace std;

using namespace CryptoPP;



string stringHash(string message)
{
    SHA256 hash;
    string digest;
    hash.Update((const byte*)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    return digest;
}

bool* generateR(short size, string key)
{
    if(size % 256 != 0)
    {
        size = 1024;
    }
    bool* r = new bool[size];
    short bitPosition;

    for(int segment = 0; segment < size/256; segment++)
    { 
       key = stringHash(key);

       for(short byte = 0; byte < 32; byte++)
        {
            bitPosition = byte * 8 + segment * 256;

            r[bitPosition] = key[byte] & 128;
            r[bitPosition + 1] = key[byte] & 64; 
            r[bitPosition + 2] = key[byte] & 32;
            r[bitPosition + 3] = key[byte] & 16;
            r[bitPosition + 4] = key[byte] & 8;
            r[bitPosition + 5] = key[byte] & 4;
            r[bitPosition + 6] = key[byte] & 2;
            r[bitPosition + 7] = key[byte] & 1;        
        }
    }

    return r;
}


