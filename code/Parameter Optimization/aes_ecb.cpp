#include <iostream>
#include "Eigen/Dense"
using std::cout;
using std::cerr;
using std::endl;
#include <cstdint>
// using std::bitset;
#include <bitset>
#include <crypto++/aes.h>
using CryptoPP::AES;
#include <crypto++/modes.h>
using CryptoPP::ECB_Mode;
#include "sodium.h"
#include <boost/multiprecision/cpp_int.hpp>
using namespace boost::multiprecision;
#include "crypto++/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include "crypto++/cryptlib.h"
using CryptoPP::Exception;
#include "crypto++/hex.h"
#include "crypto++/files.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "crypto++/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <string>
using std::string;
using namespace CryptoPP;
using Eigen::Matrix;
#define n 2
#define m 10
// need to check the time for 16 byte key with 4 integers at a time, 
// and 32 byte key with 8 integers at a time. 
union un{
    byte buff[16];
    // std::bitset<128> bitset_buff;
    int int_buf[4];
    int16_t short_buff[8];
};
union un1{
    byte buff[32];
    // std::bitset<128> bitset_buff;
    int int_buf[8];
    int16_t short_buff[16];
};

int128_t byteToint(std::byte seed[16]){
    int128_t retU = -1;
    memset(&retU,0,16);
    memcpy(&retU,&seed,16);
    return retU;
}


void printArray(int16_t array[8]){
    cout<<"[ ";
    for (size_t i = 0; i < 8; i++)
    {
        cout<<array[i]<< " ,";
    }
    cout<<" ]"<<endl;  
}

// void generate_A(byte key[16]){
//     union un seed;
//     union un plain;
//     union un1 cipher; 
//     HexEncoder encoder(new FileSink(cout));
//     plain.short_buff[0] = 0;
//     plain.short_buff[1] = 0;
//     plain.short_buff[2] = 0;
//     plain.short_buff[3] = 0;
//     plain.short_buff[4] = 0;
//     plain.short_buff[5] = 0;
//     plain.short_buff[6] = 0;
//     plain.short_buff[7] = 0;
//     memcpy(&seed.buff,&key,sizeof(byte)*16);
//     ECB_Mode< AES >::Encryption encrypt;
//     encrypt.SetKey(seed.buff, sizeof(seed.buff));
//     cout<<"Key : "<<endl;
//     encoder.Put(seed.buff,sizeof(seed.buff));
//     encoder.MessageEnd();
//     cout<<endl;
//     for (int16_t i = 0; i < n; i++)
//     {
//         for (int16_t j = 0; j < m; j=j+8)
//         {
//             plain.short_buff[0] = i;
//             plain.short_buff[1] = j;
//             ArraySink cs(&cipher.buff[0],sizeof(cipher.buff));
//             ArraySource (plain.buff,sizeof(plain.buff),true,new StreamTransformationFilter(encrypt,new Redirector(cs)));
//             // encoder.Put(cipher.buff,sizeof(cipher));
//             // encoder.MessageEnd();
//             for(size_t k=0;k<8;k++){
//                 cout<<cipher.short_buff[k]<<" ";
//                 //
//                 // if j+k < m {
//                 //     a[i][j+k] = mod(cipher.short_buff[k]);
//                 // }
//             }
//             cout<<endl;
//         }
        
//     }


// }

void printSeed(union un key){
    HexEncoder encoder(new FileSink(cout));
    cout<<"Key : "<<endl;
    encoder.Put(key.buff,sizeof(key.buff));
    encoder.MessageEnd();
    cout<<endl;
}

void gen_A(union un key,Matrix<int,n,m>*A){
    union un plain;
    plain.short_buff[0] = 0;
    plain.short_buff[1] = 0;
    plain.short_buff[2] = 0;
    plain.short_buff[3] = 0;
    plain.short_buff[4] = 0;
    plain.short_buff[5] = 0;
    plain.short_buff[6] = 0;
    plain.short_buff[7] = 0;
    union un1 cipher;
    ECB_Mode< AES >::Encryption encrypt;
    encrypt.SetKey(key.buff, sizeof(key.buff));
    printSeed(key);
    for (int16_t i = 0; i < n; i++)
    {
        for (int16_t j = 0; j < m; j=j+4)
        {
            plain.short_buff[0] = i;
            plain.short_buff[1] = j;
            ArraySink cs(&cipher.buff[0],sizeof(cipher.buff));
            ArraySource (plain.buff,sizeof(plain.buff),true,new StreamTransformationFilter(encrypt,new Redirector(cs)));
            // encoder.Put(cipher.buff,sizeof(cipher));
            // encoder.MessageEnd();
            for(size_t k=0;k<4;k++){
                cout<<cipher.int_buf[k]<<" ";
                
                if (j+k < m) {
                    // mod function needs to be implemented
                    // A(i,j+k) = mod(cipher.int_buf[k]);
                }
            }
            cout<<endl;
        }
        
    }


}


int main(int argc, char const *argv[])
{
    AutoSeededRandomPool prng;
    union un plain;
    union un key;
    union un recovered;
    union un1 recover1;
    union un1 cipher;   //with padding it generates larger thing.
    Matrix<int,n,m>A;
    plain.short_buff[0] = 0;
    plain.short_buff[1] = 0;
    plain.short_buff[2] = 0;
    plain.short_buff[3] = 0;
    plain.short_buff[4] = 0;
    plain.short_buff[5] = 0;
    plain.short_buff[6] = 0;
    plain.short_buff[7] = 0;
    // byte seed[AES::DEFAULT_KEYLENGTH];
    // this is the key
    // cout<<AES::DEFAULT_KEYLENGTH<<endl;
    HexEncoder encoder(new FileSink(cout));
    // create seed
    prng.GenerateBlock(key.buff,sizeof(key.buff));
    // cout<<AES::DEFAULT_KEYLENGTH<<" "<<key.buff<<" "<<sizeof(key.buff)<<endl;
    ECB_Mode< AES >::Encryption encrypt;
    encrypt.SetKey(key.buff, sizeof(key.buff));
    // encoder.Put(plain.buff,sizeof(plain.buff));
    // encoder.MessageEnd();
    // cout<<endl;
    // ArraySink cs(&cipher.buff[0],sizeof(cipher.buff));
    // ArraySource (plain.buff,sizeof(plain.buff),true,new StreamTransformationFilter(encrypt,new Redirector(cs)));
    // printArray(plain.short_buff);
    // cout<<sizeof(plain)+AES::BLOCKSIZE<<endl;
    // cout<<cs.TotalPutLength()<<endl;
    // encoder.Put(cipher.buff,sizeof(cipher));
    // encoder.MessageEnd();
    // cout<<endl;
    cout<<"Key : "<<endl;
    encoder.Put(key.buff,sizeof(key.buff));
    encoder.MessageEnd();
    cout<<endl;
    printSeed(key);
    cout<<"From gen_A(Key)"<<endl;
    gen_A(key,&A);
    cout<<"_____________"<<endl;
    cout<<"From gen_A(Key)"<<endl;
    gen_A(key,&A);
    cout<<"_____________"<<endl;
    cout<<"in main"<<endl;
    for (int16_t i = 0; i < n; i++)
    {
        for (int16_t j = 0; j < m; j=j+4)
        {
            plain.short_buff[0] = i;
            plain.short_buff[1] = j;
            ArraySink cs(&cipher.buff[0],sizeof(cipher.buff));
            ArraySource (plain.buff,sizeof(plain.buff),true,new StreamTransformationFilter(encrypt,new Redirector(cs)));
            // encoder.Put(cipher.buff,sizeof(cipher));
            // encoder.MessageEnd();
            for(size_t k=0;k<4;k++){
                cout<<cipher.int_buf[k]<<" ";
                //
                // if j+k < m {
                //     a[i][j+k] = mod(cipher.short_buff[k]);
                // }
            }
            cout<<endl;
        }
        
    }
    cout<<"_____________"<<endl;

    // generate_A(key.buff);
    // cout<<"_____________"<<endl;

    // generate_A(key.buff);
    // ECB_Mode< AES >::Encryption encrypt;
    encrypt.SetKey(key.buff, sizeof(key.buff));
    cout<<"Key : "<<endl;
    encoder.Put(key.buff,sizeof(key.buff));
    encoder.MessageEnd();
    cout<<endl;
    cout<<"From main"<<endl;
    for (int16_t i = 0; i < n; i++)
    {
        for (int16_t j = 0; j < m; j=j+4)
        {
            plain.short_buff[0] = i;
            plain.short_buff[1] = j;
            ArraySink cs(&cipher.buff[0],sizeof(cipher.buff));
            ArraySource (plain.buff,sizeof(plain.buff),true,new StreamTransformationFilter(encrypt,new Redirector(cs)));
            // encoder.Put(cipher.buff,sizeof(cipher));
            // encoder.MessageEnd();
            for(size_t k=0;k<4;k++){
                cout<<cipher.int_buf[k]<<" ";
                //
                // if j+k < m {
                //     a[i][j+k] = mod(cipher.short_buff[k]);
                // }
            }
            cout<<endl;
        }
        
    }
    



    // ECB_Mode< AES >::Decryption decrypt;
    // decrypt.SetKey(key.buff, sizeof(key.buff));
    // ArraySink rs(&recovered.buff[0],sizeof(recovered.buff));
    // ArraySource (cipher.buff,sizeof(cipher.buff),true,new StreamTransformationFilter(decrypt,new Redirector(rs)));
    // cout<<rs.TotalPutLength()<<endl;
    // encoder.Put(recovered.buff,sizeof(recovered.buff));
    // encoder.MessageEnd();
    // cout<<endl;
    return 0;
}
