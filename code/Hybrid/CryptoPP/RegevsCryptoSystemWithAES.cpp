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
// #define q 2000
dtype q = 20000;
// #define n 30
// #define m 270
#define n 500
#define m 1000
#define e_min -1
#define e_max 1
#define PI 3.14
// define the number of bits in the bit stream
#define numberBits 256

// byte array to hols the hash values
byte *sigma;
// hash value
byte *hashBytes = new byte[32];

// structures
// public key
struct publicKey
{
    // Matrix<dtype, n, m> A;
    // Matrix<dtype, 1, m> bT;
    dtype **A;
    dtype **bT;
};

// private key
struct privateKey
{
    // Matrix<dtype, n, m> A;
    // Matrix<dtype, 1, n> sT;
    dtype **A;
    dtype **sT;
};

// cipher text
struct cipherText
{
    // Matrix<dtype, n, numberBits> u;
    // Matrix<dtype, 1, numberBits> u_;
    dtype **u;
    dtype **u_;
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
// end genarating A matrix with seed

dtype half(dtype q)
{
    if ((q & 1) == 1)
    {
        return (q >> 1) + 1;
    }
    else
    {
        return q >> 1;
    }
}

// load public key
void loadPublicKey(publicKey *public_key)
{
    // initializing bT
    public_key->bT = initMatrix(public_key->bT, 1, m);
    // input file stream
    ifstream fin;
    fin.open("public_key.bin", ios::binary | ios::in);
    loadMatrix(&fin, public_key->bT, 1, m);
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
    private_key->sT = initMatrix(private_key->sT, 1, n);
    // input file stream
    ifstream fin;
    fin.open("private_key.bin", ios::binary | ios::in);
    // loadMatrix(&fin, private_key->sT, 1, n);
    hashBytes = loadHash(&fin, hashBytes);
    // filing sT matrix
    fillWithRandomDtype(private_key->sT, 1, n, hashBytes, q);


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
void dumpRegevCipherText(struct cipherText ct)
{
    // dumping the cipher text
    ofstream fout;
    fout.open("cipher_2.bin", ios::binary | ios::out);
    dumpMatrix(&fout, ct.u, n, numberBits);
    dumpMatrix(&fout, ct.u_, 1, numberBits);
    fout.close();
}

// dump regev ciper text
struct cipherText loadRegevCipherText()
{
    struct cipherText ct;
    ct.u = initMatrix(ct.u, n, numberBits);
    ct.u_ = initMatrix(ct.u_, 1, numberBits);
    // loading the cipher text
    ifstream fin;
    fin.open("cipher_2.bin", ios::binary | ios::in);
    loadMatrix(&fin, ct.u, n, numberBits);
    loadMatrix(&fin, ct.u_, 1, numberBits);
    fin.close();

    return ct;
}

// function to genarate keys
void dumpRegevKeys()
{
    struct privateKey private_key;
    struct publicKey public_key;

    public_key.A = initMatrix(public_key.A, n, m);
    // random seed for genarating A matrix
    AutoSeededRandomPool prng;
    union un key;
    // genarating the random seed
    prng.GenerateBlock(key.buff, sizeof(key.buff));
    // genarating the matrix
    gen_A(key, public_key.A);

    private_key.sT = initMatrix(private_key.sT, 1, n);
    // Don't have to do this 
    // for (int i = 0; i < n; i++)
    // {
    //     private_key.sT[0][i] = genUniformRandomlong(0, q - 1);
    // }

    // dumping the private key
    ofstream fout;
    fout.open("private_key.bin", ios::binary | ios::out);
    // dumpMatrix(&fout, private_key.sT, 1, n);
    // dumping the hash for sT
    dumpHash(&fout, hashBytes);
    dumpKey(&fout, key);
    fout.close();

    // filling the sT matrix
    fillWithRandomDtype(private_key.sT, 1, n, hashBytes, q);
    //double alpha = 0.0127;
    double alpha = sqrt(double(n)) / q;
    double sigma = alpha / sqrt(2 * PI);

    // Matrix<dtype, 1, m> eT;
    dtype **eT;
    eT = initMatrix(eT, 1, m);

    // dtype total = 0;
    fillWithGaussianValues(sigma, q, eT, 1, m, hashBytes);
    // for (int i = 0; i < m; i++)
    // {
    //     // e should be small and should choosen between -7,7 (discreate gausisan distribution [ignore for now])
    //     eT[0][i] = gaussian(sigma);
    //     // total += eT(col);
    // }
    // cout << "[DEBUG] min e: " << eT.minCoeff() << " max e: " << eT.maxCoeff() << " total :" << total << endl;

    // calculating bT
    // public_key->bT = (private_key->sT) * (public_key->A) + eT;
    public_key.bT = initMatrix(public_key.bT, 1, m);
    matMulAdd(private_key.sT, public_key.A, eT, public_key.bT, 1, n, m, q);
    // sharig A among public and private key
    // private_key->A = public_key->A;

    // dumping the public key
    fout.open("public_key.bin", ios::binary | ios::out);
    dumpMatrix(&fout, public_key.bT, 1, m);
    dumpKey(&fout, key);
    fout.close();
}

// function to genarate keys
void genarateRegevKeys(privateKey *private_key, publicKey *public_key)
{
    // cout << "[LOG] Generating Matrix A" << endl;

    // Genarating the matrix A
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

    // genarating the s matrix
    // cout << "[LOG] Generating Matrix s" << endl;
    // initializing matrix sT
    private_key->sT = initMatrix(private_key->sT, 1, n);
    fillWithRandomDtype(private_key->sT, 1, n, hashBytes, q);
    // for (int i = 0; i < n; i++)
    // {
    //     private_key->sT[0][i] = genUniformRandomlong(0, q - 1);
    // }
    // cout << "[DEBUG] Min of s : " << private_key->sT.minCoeff() << " Max of s : " << private_key->sT.maxCoeff() << endl;
    // cout << "[LOG] Done" << endl;

    // genarating the error matrix
    // cout << "[LOG] Generating Matrix e" << endl;
    double alpha = sqrt(double(n)) / q;
    double sigma = alpha / sqrt(2 * PI);

    // Matrix<dtype, 1, m> eT;
    dtype **eT;
    eT = initMatrix(eT, 1, m);

    // dtype total = 0;
    fillWithGaussianValues(sigma, q, eT, 1, m, hashBytes);
    // for (int i = 0; i < m; i++)
    // {
    //     // e should be small and should choosen between -7,7 (discreate gausisan distribution [ignore for now])
    //     eT[0][i] = gaussian(sigma);
    //     // total += eT(col);
    // }
    // cout << "[DEBUG] min e: " << eT.minCoeff() << " max e: " << eT.maxCoeff() << " total :" << total << endl;

    // calculating bT
    // public_key->bT = (private_key->sT) * (public_key->A) + eT;
    public_key->bT = initMatrix(public_key->bT, 1, m);
    matMulAdd(private_key->sT, public_key->A, eT, public_key->bT, 1, n, m, q);

    // taking the modulus values of bT
    // for (dtype col = 0; col < public_key->bT.cols(); col++)
    // {
    //     public_key->bT(col) = mod(public_key->bT(col), q);
    // }

    // cout << "[DEBUG] Min of B : " << public_key->bT.minCoeff() << " Max of B : " << public_key->bT.maxCoeff() << endl;

    // sharig A among public and private key
    private_key->A = public_key->A;
}

// Regev Encrypting Function
cipherText encryptRegev(publicKey public_key, short *message_bit)
{
    struct cipherText cipher_text;

    // Genarating the X matrix with random values
    // Matrix<dtype, m, numberBits> X;
    dtype **x;
    // initializing the matrix
    x = initMatrix(x, m, numberBits);

    // filling x matrix
    fillWithRandomBinary(x, n, numberBits, hashBytes);
    // for (dtype i = 0; i < m; i++)
    // {
    //     for (dtype j = 0; j < numberBits; j++)
    //     {
    //         x[i][j] = genUniformRandomlong(0, 1);
    //     }
    // }
    // cout<<"[DEBUG] min of X : "<<X.minCoeff()<<" max of X : "<<X.maxCoeff()<<endl;
    // u = AX
    // intializing u matix
    cipher_text.u = initMatrix(cipher_text.u, n, numberBits);
    // cipher_text.u = (public_key.A) * X;
    matMul(public_key.A, x, cipher_text.u, n, m, numberBits, q);
    // cout<<"[DEBUG] min of u : "<<cipher_text.u.minCoeff()<<" max of u : "<<cipher_text.u.maxCoeff()<<endl;

    // defining bTx
    // Matrix<dtype, 1, numberBits> bTx;
    dtype **bTx;
    // initializing the matrix
    bTx = initMatrix(bTx, 1, numberBits);

    // bTx = public_key.bT * X;
    matMul(public_key.bT, x, bTx, 1, m, numberBits, q);

    // // // taking the modulus of bTx
    // // for (dtype i = 0; i < numberBits; i++)
    // // {
    // //     bTx(0, i) = mod(bTx(0, i), q);
    // // }

    // // encrypting the bits
    // initalizing u_
    cipher_text.u_ = initMatrix(cipher_text.u_, 1, numberBits);
    for (int i = 0; i < numberBits; i++)
    {
        cipher_text.u_[0][i] = mod((bTx[0][i] + (message_bit[i] * half(q))), q);
    }

    // // cout<<"[DEBUG] u' : " <<cipher_text.u_ <<endl;
    return cipher_text;
}

// Regev Decrypting Funciton
short *decryptRegev(privateKey private_key, cipherText cipher_text)
{
    // defining sTu
    // Matrix<dtype, 1, numberBits> sTu;
    dtype **sTu;
    // initializing the matrix
    sTu = initMatrix(sTu, 1, numberBits);

    // sTu = (private_key.sT) * (cipher_text.u);
    matMul(private_key.sT, cipher_text.u, sTu, 1, n, numberBits, q);
    // array to hold the recoverd bits
    short *recovered = new short[numberBits];
    dtype difference = 0;

    for (dtype i = 0; i < numberBits; i++)
    {
        // recovering the single bit message
        difference = mod(cipher_text.u_[0][i] - sTu[0][i], q);
        if ((difference > (q / 4)) & (difference < (3 * q / 4)))
        { // bit is 1
            recovered[i] = 1;
        }
        else
        {
            recovered[i] = 0;
        }
    }

    return recovered;
}

// check the correctness
bool checkAnswer(dtype message_bits[numberBits], dtype recovered_bits[numberBits])
{
    dtype correctBits = 0;
    for (dtype i = 0; i < numberBits; i++)
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

// print an array of bits
void printBits(dtype bit_array[numberBits])
{
    for (dtype i = 0; i < numberBits; i++)
    {
        cout << bit_array[i];
    }
}

int main(int argc, char const *argv[])
{
    double time;
    // calculating q
    // unsigned long tmp1 = 1;
    // tmp1 = tmp1 << 31;
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
        dumpRegevKeys();

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
        cipherText cipher_text = encryptRegev(public_key, aesDataBin);
        // dump the ciper text
        dumpRegevCipherText(cipher_text);
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
        cipherText cipher_text_2 = loadRegevCipherText();
        // decrypting AES Key data using Regev
        short *aesDataBinRecovered = decryptRegev(private_key, cipher_text_2);
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