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
dtype k = 3;
dtype powOfq = 11;
dtype q = 2 ^ powOfq;
// #define n 30
// #define m 270
#define n 2
#define m 12 // resulting matrix A nxm => m = 2(nxk)
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
    // trapdoor
    dtype **G;
};

// private key
struct privateKey
{
    // Matrix<dtype, n, m> A;
    // Matrix<dtype, 1, n> sT;
    dtype **A;
    dtype **sT;

    //trapdoor
    dtype **R;
};

// cipher text
struct cipherText
{
    // Matrix<dtype, n, numberBits> u;
    // Matrix<dtype, 1, numberBits> u_;
    dtype **u;
    dtype **u_;
};

void fillWithGaussianValuesSTD(double sigma, dtype q, dtype **mat, short row, short col) //, byte *hashBytes)
{
    // recalculating the hash
    // byteHash(hashBytes, sizeof(hashBytes), hashBytes);
    // genarating the seed value
    uint32_t randomSeed = randombytes_random();
    // randomSeed = (randomSeed << 8) | hashBytes[1];
    // randomSeed = (randomSeed << 8) | hashBytes[2];
    // randomSeed = (randomSeed << 8) | hashBytes[3];

    mt19937 gen(randomSeed);
    normal_distribution<double> gauss_dis(0, sigma);
    // filling tge matrix
    for (int rowIndex = 0; rowIndex < row; rowIndex++)
    {
        for (int colIndex = 0; colIndex < col; colIndex++)
        {
            double val = gauss_dis(gen);
            if (val > 0.5)
                val = val - 1.0;
            else if (val < -0.5)
                val = val + 1;
            mat[rowIndex][colIndex] = (dtype)(val * q);
        }
    }
}

// resulting matrix A nxm => m = 2(nxk)
void mergeMatrix(dtype **mat1, dtype **mat2, dtype **result)
{
    int limit = n * k;
    // Merge the two matrices
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < limit; j++)
        {
            // To store elements of matrix mat1
            result[i][j] = mat1[i][j];

            // To store elements of matrix mat2
            result[i][j + limit] = mat2[i][j];
        }
    }

    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < m; j++)
            cout << result[i][j] << " ";
        cout << endl;
    }
}

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
            for (size_t p = 0; p < 4; p++)
            {
                // cout << cipher.int_buf[k] << " ";

                if (j + p < m)
                {
                    // mod function needs to be implemented
                    A[i][j + k] = mod(cipher.int_buf[p], q);
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
void dumpRegevKeys() ///////////////////////////////////////////////////////////////////////////
{
    struct privateKey private_key;
    struct publicKey public_key;
    union un key;

    public_key.A = initMatrix(public_key.A, n, m); // public key A
    dtype **A_ = initMatrix(A_, n, n * k);         // trapdoor A_
    dtype **g = initMatrix(g, 1, k);               // trapdoor g
    dtype **G = initMatrix(G, n, n * k);           // trapdoor G

    fillWithRandomDtype(A_, n, n * k, hashBytes, q); // A_ is filled with uniformly random values

    double alpha = sqrt(double(n)) / q;
    double sigma = alpha / sqrt(2 * PI);

    // Matrix<dtype, 1, m> eT;
    dtype **eT;
    eT = initMatrix(eT, 1, m);

    private_key.R = initMatrix(private_key.R, n * k, n * k);
    fillWithGaussianValuesSTD(sigma, q, private_key.R, n * k, n * k);

    //fillWithGaussianValues(sigma, q, eT, n*k, n*k, private_key.R);  // R pvt key filled by gaussian values
    //????????  need a gaussian value generator ??????????
    dtype **A_R = initMatrix(A_R, n, n * k);             // trapdoor A_*R mutiplication result holder
    cout << "multiplication starts" << endl;
    matMul(A_, private_key.R, A_R, n, n*k, n*k, q); // get A_*R
    cout << "multiplication done" << endl;
    dtype **GsubA_R = initMatrix(GsubA_R, n, n * k); // to hold G - A_R

    for (int row = 0; row < n; ++row)
    {
        for (int col = 0; col < k; ++col)
        {
            G[row][k * row + col] = 1 << col; // G matrix is created
        }
    }

    matSub(G, A_R, n, n * k, GsubA_R, q); // G - A_R



    // merging matrixes A_ and GsubA_R
    cout << "merge starts" << endl;
    mergeMatrix(A_, GsubA_R, public_key.A);
    cout << "merge done" << endl;

    // random seed for genarating A matrix

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