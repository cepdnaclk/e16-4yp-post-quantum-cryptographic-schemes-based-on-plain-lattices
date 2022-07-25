// input(initial vector,hash message)
#include <iostream>
#include <cstdint>
#include <cstring>
#include "../Hash/hash.h"
using namespace std;

void generateValues(byte[32] oldHash,byte[32] newHash){
    // newhash =  sha256(oldhash);
}

void initHash()



int main(int argc, char const *argv[])
{
    const char s1[] = "Hello World";
    int n = sizeof(s1);
    unsigned char input[n+1];
    strcpy((char*)input,s1);
    string hash = sha256(input);
    cout<<hash<<endl;
    return 0;
}
