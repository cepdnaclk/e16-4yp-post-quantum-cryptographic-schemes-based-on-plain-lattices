#include <iostream>

int mod(int value, int mod_value)
{
    return ((value % mod_value) + mod_value) % mod_value;
}
int invertTrapdoor(int *b, int q, int k)
{
    int s = 0;
    int sum = 0;
    for (int i = 0; i < k; i++)
    {
        std::cout << "i: " << i << " sum: " << sum << " b[k-1-i]: " << b[k - 1 - i] << " b[-k-1-i] -sum: " << b[k - 1 - i] - sum;
        // if b[k-1-i] - sum is closer to q/2 than it is to zero, s[i] is 1. else 0.
        /*
        if 3q/4 > b[k-1-i] - sum > q/4
            s = s | 1>>i
            sum = sum>>1 + 1<<(k-2-i)
        else
            sum = sum>>1
        */
        if (mod(b[k - 1 - i] - sum, q) > q / 4 && mod(b[k - 1 - i] - sum, q) < 3 * q / 4)
        {
            s = s | 1 << i;
            sum = (sum >> 1) + (1 << (k - 2 - i));
            std::cout << " bit: 1" << std::endl;
        }
        else
        {
            sum = sum >> 1;
            std::cout << " bit: 0" << std::endl;
        }
    }
    return s;
}
int main(int argc, char const *argv[])
{
    int k = 10;
    int q = 1024;
    int b[10] = {112, 414, 765, 124, 987, 752, 657, 123, 789, 234};
    std::cout << invertTrapdoor(b, q, k) << std::endl;

    return 0;
}
