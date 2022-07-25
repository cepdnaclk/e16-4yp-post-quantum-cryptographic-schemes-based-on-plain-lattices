#include <iostream>
#include <thread>
#include <boost/multiprecision/cpp_int.hpp>

// typedef long long dtype;
typedef int dtype;

// for the multiplications and additions of elements not larger than long long
// initializing the 2D matrix
dtype **initMatrix(dtype **A, int row, int col);
// matrix multiplication for threaded application
void matMulSegment(dtype **mat1, dtype **mat2, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q);
// matrix multiplication and addition for threaded application
void matMulAddSegment(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q);
// multiply matricies
void matMul(dtype **mat1, dtype **mat2, dtype **result, int r1, int c, int r2, dtype q);
// multiply matricies
void matMulAdd(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1, int c, int r2, dtype q);

// for the multiplications and additions of elements larger than long long
// matrix multiplication for threaded application
void matMulSegmentLarge(dtype **mat1, dtype **mat2, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q);
// matrix multiplication and addition for threaded application
void matMulAddSegmentLarge(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q);
// multiply matricies
void matMulLarge(dtype **mat1, dtype **mat2, dtype **result, int r1, int c, int r2, dtype q);
// multiply matricies
void matMulAddLarge(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1, int c, int r2, dtype q);


// mod oparation
dtype mod(dtype value, dtype mod_value);