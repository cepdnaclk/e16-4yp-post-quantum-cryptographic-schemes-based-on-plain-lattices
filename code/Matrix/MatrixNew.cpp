#include "Matrix.h"

using namespace std;
using namespace boost::multiprecision;
// typedef long long dtype;

// modulus function
dtype mod(dtype value, dtype mod_value)
{
    return ((value % mod_value) + mod_value) % mod_value;
}

dtype element_mul(dtype val1, dtype val2, dtype q)
{

    if (val1 == 0 || val2 == 0)
    {
        return (dtype)0;
    }
    int128_t result = (int128_t)val1 * val2;
    // first get modulo by q and then cast it to dtype
    dtype mod_res = (dtype)(result % q);
    // use mod again to map between[0,q)
    return mod(mod_res, q);
}
// Matrix oparations =================================

// initializing the 2D matrix
dtype **initMatrix(dtype **A, int row, int col)
{
    A = new dtype *[row];
    for (int i = 0; i < row; i++)
        A[i] = new dtype[col];
    return A;
}

// for the multiplications not larger than long long

// matrix multiplication for threaded application
void matMulSegment(dtype **mat1, dtype **mat2, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q)
{

    for (int i = r1_start; i < r1_stop; i++)
    {
        for (int j = 0; j < r2; j++)
        {
            result[i][j] = 0;

            for (int k = 0; k < c; k++)
            {
                dtype mul = 0;
                if (mat1[i][k] && mat2[k][j])
                    mul = mat1[i][k] * mat2[k][j];
                mul = mod(mul, q);
                result[i][j] += mul;
                result[i][j] = mod(result[i][j], q);
            }
        }
    }
}

// matrix multiplication and addition for threaded application
void matMulAddSegment(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q)
{

    for (int i = r1_start; i < r1_stop; i++)
    {
        for (int j = 0; j < r2; j++)
        {
            result[i][j] = mat3[i][j];

            for (int k = 0; k < c; k++)
            {
                dtype mul = mat1[i][k] * mat2[k][j];
                mul = mod(mul, q);
                result[i][j] += mul;
                result[i][j] = mod(result[i][j], q);
            }
        }
    }
}

// multiply matricies
void matMul(dtype **mat1, dtype **mat2, dtype **result, int r1, int c, int r2, dtype q)
{
    // note - resultent matrix should be initialized before calling this function
    //  initializing the thread matrix
    thread th1(matMulSegment, mat1, mat2, result, 0, r1 / 4, c, r2, q);
    thread th2(matMulSegment, mat1, mat2, result, r1 / 4, r1 / 2, c, r2, q);
    thread th3(matMulSegment, mat1, mat2, result, r1 / 2, 3 * r1 / 4, c, r2, q);
    thread th4(matMulSegment, mat1, mat2, result, 3 * r1 / 4, r1, c, r2, q);

    // joining the threads
    th1.join();
    th2.join();
    th3.join();
    th4.join();
}

// multiply matricies
void matMulAdd(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1, int c, int r2, dtype q)
{
    // note - resultent matrix should be initialized before calling this function
    //  initializing the thread matrix
    thread th1(matMulAddSegment, mat1, mat2, mat3, result, 0, r1 / 4, c, r2, q);
    thread th2(matMulAddSegment, mat1, mat2, mat3, result, r1 / 4, r1 / 2, c, r2, q);
    thread th3(matMulAddSegment, mat1, mat2, mat3, result, r1 / 2, 3 * r1 / 4, c, r2, q);
    thread th4(matMulAddSegment, mat1, mat2, mat3, result, 3 * r1 / 4, r1, c, r2, q);

    // joining the threads
    th1.join();
    th2.join();
    th3.join();
    th4.join();
}

// for the multiplications larger than long long

// matrix multiplication for threaded application
void matMulSegmentLarge(dtype **mat1, dtype **mat2, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q)
{

    for (int i = r1_start; i < r1_stop; i++)
    {
        for (int j = 0; j < r2; j++)
        {
            result[i][j] = 0;

            for (int k = 0; k < c; k++)
            {
                dtype mul = 0;
                if (mat1[i][k] && mat2[k][j])
                {
                    int128_t result_inter = (int128_t)mat1[i][k] * mat2[k][j];
                    // first get modulo by q and then cast it to dtype
                    dtype result_inter_mod = (dtype)(result_inter % q);
                    result_inter_mod = mod(result_inter_mod, q);

                    // doing addition
                    result_inter = result_inter_mod + result[i][j];
                    result_inter_mod = (dtype)(result_inter % q);
                    result_inter_mod = mod(result_inter_mod, q);

                    result[i][j] = result_inter_mod;
                }
            }
        }
    }
}

// matrix multiplication and addition for threaded application
void matMulAddSegmentLarge(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q)
{

    for (int i = r1_start; i < r1_stop; i++)
    {
        for (int j = 0; j < r2; j++)
        {
            result[i][j] = mat3[i][j];

            for (int k = 0; k < c; k++)
            {
                if (mat1[i][k] && mat2[k][j])
                {
                    int128_t result_inter = (int128_t)mat1[i][k] * mat2[k][j];
                    // first get modulo by q and then cast it to dtype
                    dtype result_inter_mod = (dtype)(result_inter % q);
                    result_inter_mod = mod(result_inter_mod, q);

                    // doing addition
                    result_inter = result_inter_mod + result[i][j];
                    result_inter_mod = (dtype)(result_inter % q);
                    result_inter_mod = mod(result_inter_mod, q);

                    result[i][j] = result_inter_mod;
                }
            }
        }
    }
}

// multiply matricies
void matMulLarge(dtype **mat1, dtype **mat2, dtype **result, int r1, int c, int r2, dtype q)
{
    // note - resultent matrix should be initialized before calling this function
    //  initializing the thread matrix
    thread th1(matMulSegmentLarge, mat1, mat2, result, 0, r1 / 4, c, r2, q);
    thread th2(matMulSegmentLarge, mat1, mat2, result, r1 / 4, r1 / 2, c, r2, q);
    thread th3(matMulSegmentLarge, mat1, mat2, result, r1 / 2, 3 * r1 / 4, c, r2, q);
    thread th4(matMulSegmentLarge, mat1, mat2, result, 3 * r1 / 4, r1, c, r2, q);

    // joining the threads
    th1.join();
    th2.join();
    th3.join();
    th4.join();
}

// multiply matricies
void matMulAddLarge(dtype **mat1, dtype **mat2, dtype **mat3, dtype **result, int r1, int c, int r2, dtype q)
{
    // note - resultent matrix should be initialized before calling this function
    //  initializing the thread matrix
    thread th1(matMulAddSegmentLarge, mat1, mat2, mat3, result, 0, r1 / 4, c, r2, q);
    thread th2(matMulAddSegmentLarge, mat1, mat2, mat3, result, r1 / 4, r1 / 2, c, r2, q);
    thread th3(matMulAddSegmentLarge, mat1, mat2, mat3, result, r1 / 2, 3 * r1 / 4, c, r2, q);
    thread th4(matMulAddSegmentLarge, mat1, mat2, mat3, result, 3 * r1 / 4, r1, c, r2, q);

    // joining the threads
    th1.join();
    th2.join();
    th3.join();
    th4.join();
}

void matMulBin(dtype **mat1, boost::dynamic_bitset<> &vector, dtype **result, int r1, int c, int r2, dtype q);
{
    // matrix dimensions : r1*c
    if (sizeof(vector) * 8 < c)
    {
        // not enough values to unpack
        std::cout << "Not enough bits to unpack in the vector" << std::endl;
        return;
    }
    thread th1(matMulSegmentBin, mat1, vector, result, 0, r1 / 4, c, r2, q);
    thread th2(matMulSegmentBin, mat1, vector, result, r1 / 4, r1 / 2, c, r2, q);
    thread th3(matMulSegmentBin, mat1, vector, result, r1 / 2, 3 * r1 / 4, c, r2, q);
    thread th4(matMulSegmentBin, mat1, vector, result, 3 * r1 / 4, r1, c, r2, q);

    // joining the threads
    th1.join();
    th2.join();
    th3.join();
    th4.join();
}

void matMulSegmentBin(dtype **mat1, byte *vector, dtype **result, int r1_start, int r1_stop, int c, int r2, dtype q)
{

    for (int i = r1_start; i < r1_stop; i++)
    {
        for (int j = 0; j < r2; j++)
        {
            result[i][j] = 0;

            for (int k = 0; k < c; k++)
            {
                dtype mul = 0;
                int bit = vector[];
                if (mat1[i][k] && mat2[k][j])
                    mul = mat1[i][k] * mat2[k][j];
                mul = mod(mul, q);
                result[i][j] += mul;
                result[i][j] = mod(result[i][j], q);
            }
        }
    }
}

void matMulBinFraction(dtype **matrix, boost::dynamic_bitset<> &vec, int row_start, int row_stop, int cols, dtype *result, dtype q)
{
    int sum;
    for (int i = row_start; i < row_stop; ++i)
    {
        sum = 0;
        for (int j = 0; j < cols; ++j)
        {
            if (vec[j] == 1)
            {
                sum += mod(matrix[i][j], q);
            }
        }
        result[i] = mod(sum, q);
    }
}

void matMulBin(dtype **matrix, boost::dynamic_bitset<> &vec, int rows, int cols, dtype *result, dtype q)
{

    thread th1(matMulBinFraction, matrix, std::ref(vec), 0, rows / 4, cols, result, q);
    // std::
    thread th2(matMulBinFraction, matrix, std::ref(vec), rows / 4, rows / 2, cols, result, q);
    // std::
    thread th3(matMulBinFraction, matrix, std::ref(vec), rows / 2, 3 * rows / 4, cols, result, q);
    // std::
    thread th4(matMulBinFraction, matrix, std::ref(vec), 3 * rows / 4, rows, cols, result, q);
    th1.join();
    th2.join();
    th3.join();
    th4.join();
}

void matSub(dtype **mat1, dtype **mat2, int rows, int cols, dtype **result, dtype q)
{   


    for (int i = 0; i < rows; ++i)
    {
        for (int j = 0; j < cols; ++j)
        {
             result[i][j] = mod(mat1[i][j] - mat2[i][j], q);
        }
       
    }
}


void matMulBinByteSegment(dtype **mat1, byte **mat2, dtype **result, int row_start, int row_end, int cols, dtype q)
{
    // multiply a part of the matrix.
    // bit shifts should be used to multipy.
}

void matMulBinBytes(dtype **mat1, byte **mat2, dtype **result, int r1, int c, int r2, dtype q)
{
    // mat2 should have binary numbers. each mat2[0] entry should have bits similar to the r2 .
    // mat1: r1*c
    // mat2: c*r2
    // mat2 have c rows of byte arrays with length of r2/8. (each bit represents 0 or 1)
    //
}