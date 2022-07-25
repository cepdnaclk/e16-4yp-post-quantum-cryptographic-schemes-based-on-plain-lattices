
#include "sha256KeyGeneration.h"

int main(int argc, char const *argv[])
{
        short size = 1024;
        std::string msg = "Yoda said, Do or do not. There is no try.";
        bool* r = generateBinArray(size ,msg);


        for (short bit = 0; bit < size; bit++)
        {
            cout<<"bit = " << bit + 1 << ": " << r[bit] <<endl;
        }

}