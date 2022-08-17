/*Dual LWE CryptoSystem

g++ DualCryptoSystemWithAES.cpp -pthread -lsodium -lcryptopp -std=c++14 ../../RandomOracle/randomNumberGeneration.cpp ../../Matrix/Matrix.cpp ../../AESHelper/AESHelper.cpp ../../FileHelper/FileHelper.cpp

*/


// A is a public key

// Reciever genarates x

// Reciever sends A, u = Ax as public keys to the sender. 

//                              sender sends b' = s'A+e' (ciphertext -preamble)
//                              sender sends payload b' = s'u + e' + bit*q/2

//Reciever calculates b'-b'x. then decide 


#include <iostream>
#include <random>
#include <ctime>
#include "sodium.h"
#include "../../Matrix/Matrix.h"
// #include "../AESHelper/AESHelper.h"
#include "../../FileHelper/FileHelper.h"
#include "../../RandomOracle/randomNumberGeneration.h"
#include <cmath>
#include <chrono>

using namespace std;
using namespace std::chrono;

// defining the parameters
dtype q = 20000;
// #define n 30
// #define m 270
#define n 500
#define m 1000
#define e_min -7
#define e_max 7
#define PI 3.14

#define numberBits 256

// byte array to hols the hash values
byte *sigma;
// hash value
byte *hashBytes = new byte[32];

// structures
// public key

struct publicKey
{
    // Matrix<long, n, m> A;
    // Matrix<long, n, numberBits> u;
    dtype **A;
    dtype **u;
};

struct privateKey
{
    // Matrix<long, n, m> A;
    // Matrix<long, m, numberBits> x;
    dtype **A;
    dtype **x;
};

struct cipherText
{
    // Matrix<long, 1, m> bT;
    // Matrix<long, 1, numberBits> b_;
    dtype **bT;
    dtype **b_;
};

// genarate A matrix using a seed
void gen_A(union un key, dtype **A)
{
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
    ECB_Mode<AES>::Encryption encrypt;
    encrypt.SetKey(key.buff, sizeof(key.buff));
    // printSeed(key);
    for (int16_t i = 0; i < n; i++)
    {
        for (int16_t j = 0; j < m; j = j + 4)
        {
            plain.short_buff[0] = i;
            plain.short_buff[1] = j;
            ArraySink cs(&cipher.buff[0], sizeof(cipher.buff));
            ArraySource(plain.buff, sizeof(plain.buff), true, new StreamTransformationFilter(encrypt, new Redirector(cs)));
            // encoder.Put(cipher.buff,sizeof(cipher));
            // encoder.MessageEnd();
            for (size_t k = 0; k < 4; k++)
            {
                // cout << cipher.int_buf[k] << " ";

                if (j + k < m)
                {
                    // mod function needs to be implemented
                    A[i][j + k] = mod(cipher.int_buf[k], q);
                }
            }
            // cout << endl;
        }
    }
}

dtype half(dtype q){
    if ((q&1)==1){
        return (q>>1)+1;
    }else{
        return q>>1;
    }
}

dtype gaussian(double sigma)
{

    mt19937 gen(randombytes_random());
    normal_distribution<double> gauss_dis(0, sigma);
    double val = gauss_dis(gen);
    if (val > 0.5)
        val = val - 1.0;
    else if (val < -0.5)
        val = val + 1;
    return (dtype)(val * q);
}

// load public key
void loadPublicKey(publicKey *public_key)
{
    // initializing bT
    public_key->u = initMatrix(public_key->u, n, numberBits);
    // input file stream
    ifstream fin;
    fin.open("public_key.bin", ios::binary | ios::in);
    loadMatrix(&fin, public_key->u, n, numberBits);
    // cout << "hello" << public_key->bT[0][0] << endl;

    // key for the A matrix
    union un key;
    key = loadKey(&fin, key);

    fin.close();

    // initializing A matrix
    public_key->A = initMatrix(public_key->A, n, m);
    // genarating the matrix
    gen_A(key, public_key->A);
}

// load private key
void loadPrivateKey(privateKey *private_key)
{
    // initializing bT
    private_key->x = initMatrix(private_key->x, m, numberBits);
    // input file stream
    ifstream fin;
    fin.open("private_key.bin", ios::binary | ios::in);
    // loadMatrix(&fin, private_key->x, m, numberBits);
    hashBytes = loadHash(&fin, hashBytes);
    // fill with random binary
    fillWithRandomBinary(private_key->x, m, numberBits, hashBytes);


    // key for the A matrix
    union un key;
    key = loadKey(&fin, key);

    fin.close();

    // initializing A matrix
    private_key->A = initMatrix(private_key->A, n, m);
    // genarating the matrix
    gen_A(key, private_key->A);
}

// dump regev ciper text
void dumpDualCipherText(struct cipherText ct)
{
    // dumping the cipher text
    ofstream fout;
    fout.open("cipher_2.bin", ios::binary | ios::out);
    dumpMatrix(&fout, ct.bT, 1, m);
    dumpMatrix(&fout, ct.b_, 1, numberBits);
    fout.close();
}

// dump regev ciper text
struct cipherText loadDualCipherText()
{
    struct cipherText ct;
    ct.bT = initMatrix(ct.bT, 1, m);
    ct.b_ = initMatrix(ct.b_, 1, numberBits);
    // loading the cipher text
    ifstream fin;
    fin.open("cipher_2.bin", ios::binary | ios::in);
    loadMatrix(&fin, ct.bT, 1, m);
    loadMatrix(&fin, ct.b_, 1, numberBits);
    fin.close();

    return ct;
}

// function to genarate keys
void genarateDualKeys(privateKey* private_key, publicKey* public_key)
{
    // cout << "[LOG] Generating Matrix A" << endl;
    // Genarating the matrix A
    // long number = 0;
    // initializing matrix A
    public_key->A = initMatrix(public_key->A, n, m);
    // for (int i = 0; i < n; i++)
    // {
    //     for (int j = 0; j < m; j++)
    //     {
    //         // filling the A matrix from the numbers taken from the distribution
    //         public_key->A[i][j] = genUniformRandomlong(0, q - 1);
    //     }
    // }
    AutoSeededRandomPool prng;
    union un key;
    prng.GenerateBlock(key.buff, sizeof(key.buff));
    gen_A(key, public_key->A);

    // avarage of A's coiff should be close to q/2
    // cout << "[DEBUG] Min of A : " << public_key->A.minCoeff() << " Max of A : " << public_key->A.maxCoeff() << endl;
    // cout << "[LOG] Done" << endl;

    // genarating the x matrix
    // cout << "[LOG] Generating Matrix x" << endl;
    // initializing number x
    private_key->x = initMatrix(private_key->x, m, numberBits);
    fillWithRandomBinary(private_key->x, m, numberBits, hashBytes);
    // for (long row = 0; row < m; row++)
    // {
    //     for (long col = 0; col < numberBits; col++)
    //     {
    //         private_key->x[row][col] =  genUniformRandomlong(0, 1);
    //     }

    // }
    // cout << "[DEBUG] Min of s : " << private_key->x.minCoeff() << " Max of s : " << private_key->x.maxCoeff() << endl;
    // cout << "[LOG] Done" << endl;    
    

    // sharig A among public and private key
    private_key->A = public_key->A;
    //generate u as public key

    // initializing public ket u
    public_key->u = initMatrix(public_key->u, n, numberBits);
    // public_key->u = ((private_key->A)*(private_key->x));
    matMul(private_key->A, private_key->x, public_key->u, n, m, numberBits, q);
    
}

// function to genarate keys
void dumpDualKeys()
{
    struct privateKey private_key;
    struct publicKey public_key;

    public_key.A = initMatrix(public_key.A, n, m);

    // genarating random seed
    AutoSeededRandomPool prng;
    union un key;
    // genarating the random seed
    prng.GenerateBlock(key.buff, sizeof(key.buff));
    // genarate the matrix
    gen_A(key, public_key.A);

    private_key.x = initMatrix(private_key.x, m, numberBits);
    // for (long row = 0; row < m; row++)
    // {
    //     for (long col = 0; col < numberBits; col++)
    //     {
    //         private_key.x[row][col] =  genUniformRandomlong(0, 1);
    //     }

    // }

    // dumping the private key
    ofstream fout;
    fout.open("private_key.bin", ios::binary | ios::out);
    // dumpMatrix(&fout, private_key.x, m, numberBits);
    dumpHash(&fout, hashBytes);
    dumpKey(&fout, key);
    fout.close();
    
    // fill with random binary
    fillWithRandomBinary(private_key.x, m, numberBits, hashBytes);

    // initializing public ket u
    public_key.u = initMatrix(public_key.u, n, numberBits);
    // public_key->u = ((private_key->A)*(private_key->x));
    matMul(public_key.A, private_key.x, public_key.u, n, m, numberBits, q);

    // dumping the public key
    fout.open("public_key.bin", ios::binary | ios::out);
    dumpMatrix(&fout, public_key.u, n, numberBits);
    dumpKey(&fout, key);
    fout.close();
    
}

// encryptDualing Function
cipherText encryptDual(publicKey public_key, short message_bit[numberBits])
{
    struct cipherText cipher_text;

    // cout << "[LOG] Generating Matrix e" << endl;
    // initializing eT Matrix
    // Matrix<long, 1, m> eT;
    dtype **eT;
    eT = initMatrix(eT, 1, m);

    // long total = 0;
    double alpha = sqrt(double(n))/q;
    double sigma = alpha/sqrt(2*PI);

    fillWithGaussianValues(sigma, q, eT, 1, m, hashBytes);
    // for (long col = 0; col < m; col++)
    // {
    //     // e should be small and should choosen between -7,7 (discreate gausisan distribution [ignore for now])
    //     eT[0][col] = gaussian(sigma);
    //     // cout << eT[0][col] << endl;
    //     // total += eT(col);
    // }
    // cout << "[DEBUG] min e: " << eT.minCoeff() << " max e: " << eT.maxCoeff() << " total :" << total << endl;

    // genarating the s matrix
    // initializing sT matrix
    // Matrix<long, 1, n> sT;
    dtype **sT;
    sT = initMatrix(sT, 1, n);

    // cout << "[LOG] Generating Matrix s" << endl;
    fillWithRandomDtype(sT, 1, n, hashBytes, q);
    // for (long col = 0; col < n; col++)
    // {
    //     sT[0][col] = genUniformRandomlong(0, q-1);
    // }


    // cout << "[DEBUG] Min of s : " << sT.minCoeff() << " Max of s : " << sT.maxCoeff() << endl;
    // cout << "[LOG] Done" << endl;

    // initializing bT
    cipher_text.bT = initMatrix(cipher_text.bT, 1, m);
    // cipher_text.bT = sT * (public_key.A) + eT;
    matMulAdd(sT, public_key.A, eT, cipher_text.bT, 1, n, m, q);

    // initializing sTu
    // Matrix<long, 1, numberBits> sTu = sT * (public_key.u); 
    dtype **sTu;
    sTu = initMatrix(sTu, 1, numberBits);
    matMul(sT, public_key.u, sTu, 1, n, numberBits, q);

    // generate e'
    // Matrix<long, 1, numberBits> e_;
    
    // initializing b_
    cipher_text.b_ = initMatrix(cipher_text.b_, 1, numberBits);
    // calculating b_

    // genarating gausian matrix
    dtype **gaussianMatrix;
    gaussianMatrix = initMatrix(gaussianMatrix, 1, numberBits);
    fillWithGaussianValues(sigma, q, gaussianMatrix, 1, numberBits, hashBytes);

    for(long col = 0; col < numberBits; col++)
    {
        cipher_text.b_[0][col] = mod((sTu[0][col] + gaussianMatrix[0][col] + (message_bit[col] * (half(q)))), q);
    }


    // cout<<abs(e_- eT*private_key.x)<<endl;
    //cout<<"[DEBUG] u' : " <<cipher_text.u_ <<endl;
    return cipher_text;
}

// decryptDualing Funciton
short* decryptDual(privateKey private_key, cipherText cipher_text)
{
    // Matrix<long, 1, numberBits> bTx;
    dtype **bTx;
    // initializing bTx
    bTx = initMatrix(bTx, 1, numberBits);
    static short recovered[numberBits];

    // bTx = cipher_text.bT * private_key.x;
    matMul(cipher_text.bT, private_key.x, bTx, 1, m, numberBits, q);

    long difference = 0;

    for (long col = 0; col < numberBits; col++)
    {
        difference = mod(cipher_text.b_[0][col] - bTx[0][col], q);

        // recovering the single bit message
        if ((difference > (q / 4)) & (difference < (3 * q / 4)))
        { // bit is 1
            recovered[col] = 1;
        }
        else
            recovered[col] = 0;
    }


    return recovered;
}

// check the correctness
bool checkAnswer(short message_bits[numberBits], short recovered_bits[numberBits])
{
    long correctBits = 0;
    for (long i = 0; i < numberBits; i++)
    {
        if (message_bits[i] == recovered_bits[i])
        {
            correctBits++;
        }
    }
    // cout << "correct bits: " << correctBits << endl;
    if (correctBits == numberBits)
    {
        return true;
    }
    return false;
}

int main(int argc, char const *argv[])
{
    double time;
    // calculating q
    // unsigned long tmp1 = 1;
    // tmp1 = tmp1 << 30;
    // q = tmp1 - 19;
    cout << "q = " << q << endl;

    assert(sodium_init() == 0);

    // initiating the random number genarator with hash
    string message = "Hello";
    hashBytes = initHash(sigma, hashBytes, message);

    // Menu system
    int option;
    cout << "Hybrid Encryption System. Select the option you want" << endl;
    cout << "1. Generate Key pair" << endl;
    cout << "2. Encrypt" << endl;
    cout << "3. Decrypt" << endl;
    cout << "Enter your option: ";

    // taking user input
    cin >> option;

    if (option == 1)
    {
        auto start = high_resolution_clock::now();
        // Generating Regev keys
        dumpDualKeys();

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Key Genaration time = " << time << " s" << endl;
    }
    else if (option == 2)
    {
        auto start = high_resolution_clock::now();
        // Encryptions process ==============================================================
        // loading the public key
        struct publicKey public_key;
        loadPublicKey(&public_key);
        // cout << public_key.bT[0][0];
        // Genarating AES Key and Iv
        AESKeyAndIv aesData = generateAESKey();
        // conver to bits
        short *aesDataBin = AESDataToBinConvert(aesData);
        // encrypting AES Key Data using Regev
        cipherText cipher_text = encryptDual(public_key, aesDataBin);
        // dump the ciper text
        dumpDualCipherText(cipher_text);
        // AES Encryption Process
        encryptAES(aesData);

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Encryption time = " << time << " s" << endl;
    }
    else if (option == 3)
    {
        auto start = high_resolution_clock::now();
        // Decryption process ==============================================================
        // loading the private key
        struct privateKey private_key;
        loadPrivateKey(&private_key);
        // loading the cipher text from the file
        cipherText cipher_text_2 = loadDualCipherText();
        // decrypting AES Key data using Regev
        short *aesDataBinRecovered = decryptDual(private_key, cipher_text_2);
        // Converting binary data back to AES key and Iv
        AESKeyAndIv convertedData = binToAESData(aesDataBinRecovered);
        // AES Decryption
        decryptAES(convertedData);

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Decryption time = " << time << " s" << endl;
    }
    else
    {
        cout << "invalid option" << endl;
    }

    return 0;
}