#include <cstdio>
#include "sodium.h"
#include <string>
#include <iostream>
#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>


using namespace std;
using CryptoPP::RandomNumberGenerator;
using CryptoPP::AutoSeededRandomPool;

    // Returns a pointer to a newly created 2d array the R has size [height x width]

int** createR(unsigned height, unsigned width)
{
      int** R = 0;
      R = new int*[height];
      uint32_t randomNumber;
      AutoSeededRandomPool rnd;
      byte key[width];
    
      for (int h = 0; h < height; h++)
      {
            R[h] = new int[width];
            

            rnd.GenerateBlock(key, width);
           
            for (int w = 0; w < width; w++)
            {
                  // fill in some initial values
                  // (filling in zeros would be more logic, but this is just for the example)
                  //R[h][w] = w + width * h;
                cout << (int)key[w] << " " ;
            }
            cout<< "" << endl;
      }
    
      return R;
}


    
int main()
    {
    
      printf("Creating a 2D R\n");
      printf("\n");
    
      int height = 10;
      int width = 10;
      int** my2DArray = createR(height, width);
      printf("Array sized [%i,%i] created.\n\n", height, width);
    
      // print contents of the R
      printf("Array contents: \n");
    
      for (int h = 0; h < height; h++)
      {
            for (int w = 0; w < width; w++)
            {
                  printf("%i,", my2DArray[h][w]);
            }
            printf("\n");
      }
    
          // important: clean up memory
          printf("\n");
          printf("Cleaning up memory...\n");
          for (int h = 0; h < height; h++) // loop variable wasn't declared
          {
            delete [] my2DArray[h];
          }
          delete [] my2DArray;
          my2DArray = 0;
          printf("Ready.\n");
    

        //uint32_t randomNumber = randombytes_random();

        //cout << randomNumber << endl;
      return 0;
    }