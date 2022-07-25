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

union un
{
    byte buff[16];
    int int_buf[4];
    int16_t short_buff[8];
};
union un1
{
    byte buff[32];
    int int_buf[8];
    int16_t short_buff[16];
};
using namespace CryptoPP;
int main(int argc, char const *argv[])
{
    union un1 hash_digest;
    HexEncoder encoder(new FileSink(std::cout));

    std::string msg = "Yoda said, Do or do not. There is no try.";
    std::string digest;

    SHA256 hash;
    hash.Update((const byte *)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte *)&digest[0]);
    hash.Final(hash_digest.buff);

    std::cout << "Message: " << msg << std::endl;

    std::cout << "Digest: ";
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;
    // ArraySource(hash_digest.buff, true, new Redirector(encoder));
    // std::cout << std::endl;
    std::cout << sizeof(digest) << std::endl;
    std::cout << "Key : " << std::endl;
    encoder.Put(hash_digest.buff, sizeof(hash_digest.buff));
    encoder.MessageEnd();
    std::cout << std::endl;
}
