#include <iostream>
#include"AESHelper.h"

using namespace std;
// for AES
using CryptoPP::AES;
using CryptoPP::AutoSeededRandomPool;
// using byte;
using CryptoPP::CTR_Mode;
using CryptoPP::Exception;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::MeterFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::word64;

using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::ECB_Mode;

AESKeyAndIv generateAESKey()
{
    // structure to hold AES Data
    struct AESKeyAndIv aesData;

    AutoSeededRandomPool rnd;
    rnd.GenerateBlock(aesData.key, AESKeyLength);
    rnd.GenerateBlock(aesData.iv, AESIvLength);

    return aesData;
}

void printSeed(union un key)
{
    HexEncoder encoder(new FileSink(cout));
    cout << "Key : " << endl;
    encoder.Put(key.buff, sizeof(key.buff));
    encoder.MessageEnd();
    cout << endl;
}

// convert byte array to bin
short *AESDataToBinConvert(AESKeyAndIv data)
{
    // binary bit stream
    short *bitstream = new short[(AESKeyLength + AESIvLength) * 8];

    // iterator for the array
    int index = 0;

    // converting the key
    for (int i = 0; i < AESKeyLength; ++i)
    {
        for (int j = 0; j < 8; ++j)
        {
            bitstream[index] = (data.key[i] >> j) & 1;
            index++;
        }
    }
    // converting the IV
    for (int i = 0; i < AESIvLength; ++i)
    {
        for (int j = 0; j < 8; ++j)
        {
            bitstream[index] = (data.iv[i] >> j) & 1;
            index++;
        }
    }

    return bitstream;
}

// convert binary to AES key and IV
AESKeyAndIv binToAESData(short bitstream[(AESKeyLength + AESIvLength)])
{

    byte *bytestream = new byte[AESKeyLength];
    struct AESKeyAndIv data;

    // helper varibles
    // short binValues[8] = {128, 64, 32, 16, 8, 4, 2, 1};
    short binValues[8] = {1, 2, 4, 8, 16, 32, 64, 128};
    short total = 0;
    short bytePosition = 0;

    // calculating key
    for (int i = 1; i < AESKeyLength * 8 + 1; ++i)
    {
        total = total + (bitstream[i - 1] * binValues[(i - 1) % 8]);

        // resetting for new byte
        if (i % 8 == 0)
        {
            data.key[bytePosition] = (byte)total;
            total = 0;
            bytePosition++;
        }
    }

    // resetting for iv
    total = 0;
    bytePosition = 0;

    // calculating iv
    for (int i = 1; i < AESIvLength * 8 + 1; ++i)
    {
        total = total + bitstream[(AESKeyLength * 8) + i - 1] * binValues[(i - 1) % 8];

        if (i % 8 == 0)
        {
            data.iv[bytePosition] = (byte)total;
            total = 0;
            bytePosition++;
        }
    }

    return data;
}

// AES Helper funciton
inline bool EndOfFile(const FileSource &file)
{
    std::istream *stream = const_cast<FileSource &>(file).GetStream();
    return stream->eof();
}

// AES Encryption Function
void encryptAES(AESKeyAndIv data)
{
    try
    {
        byte key[AES::DEFAULT_KEYLENGTH] = {}, iv[AES::BLOCKSIZE] = {};
        CTR_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(data.key, sizeof(data, key), iv);

        MeterFilter meter;
        StreamTransformationFilter filter(encryptor);

        FileSource source("plain.jpg", false);
        FileSink sink("cipher.bin");

        source.Attach(new Redirector(filter));
        filter.Attach(new Redirector(meter));
        meter.Attach(new Redirector(sink));

        const word64 BLOCK_SIZE = 4096;
        word64 processed = 0;

        while (!EndOfFile(source) && !source.SourceExhausted())
        {
            source.Pump(BLOCK_SIZE);
            filter.Flush(false);

            processed += BLOCK_SIZE;

            if (processed % (1024 * 1024 * 10) == 0)
                cout << "Processed: " << meter.GetTotalBytes() << endl;
        }

        // Signal there is no more data to process.
        // The dtor's will do this automatically.
        filter.MessageEnd();

        cout << "Encryption Complete" << endl;
    }
    catch (const Exception &ex)
    {
        cerr << ex.what() << endl;
    }
}

// AES Decryption Function
void decryptAES(AESKeyAndIv data)
{
    try
    {
        byte key[AES::DEFAULT_KEYLENGTH] = {}, iv[AES::BLOCKSIZE] = {};
        CTR_Mode<AES>::Encryption decryptor;
        decryptor.SetKeyWithIV(data.key, sizeof(data, key), iv);

        MeterFilter meter;
        StreamTransformationFilter filter(decryptor);

        FileSource source("cipher.bin", false);
        FileSink sink("recovered.jpg");

        source.Attach(new Redirector(filter));
        filter.Attach(new Redirector(meter));
        meter.Attach(new Redirector(sink));

        const word64 BLOCK_SIZE = 4096;
        word64 processed = 0;

        while (!EndOfFile(source) && !source.SourceExhausted())
        {
            source.Pump(BLOCK_SIZE);
            filter.Flush(false);

            processed += BLOCK_SIZE;

            if (processed % (1024 * 1024 * 10) == 0)
                cout << "Processed: " << meter.GetTotalBytes() << endl;
        }

        // Signal there is no more data to process.
        // The dtor's will do this automatically.
        filter.MessageEnd();

        cout << "Decryption Complete" << endl;
    }
    catch (const Exception &ex)
    {
        cerr << ex.what() << endl;
    }
}