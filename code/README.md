# Efficient Implementations of Post Quantum Cryptographic Schemes Based on Plain Lattices

___

## Pre-requisites

1. libsodium\
sudo apt-get install -y libsodium-dev
2. boost\
sudo apt-get install libboost-all-dev
3. cryptoPP\
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils

## How-to-compile

1. go to Hybrid/cryptopp folder

2. g++ RegevsCryptoSystemWithAES.cpp -o regevAES -pthread -lsodium -lcryptopp -std=c++14 ../../RandomOracle/randomNumberGeneration.cpp ../../Matrix/Matrix.cpp ../../AESHelper/AESHelper.cpp ../../FileHelper/FileHelper.cpp

3. g++ DualCryptoSystemWithAES.cpp -o dualAES -pthread -lsodium -lcryptopp -std=c++14 ../../RandomOracle/randomNumberGeneration.cpp ../../Matrix/Matrix.cpp ../../AESHelper/AESHelper.cpp ../../FileHelper/FileHelper.cpp

4. run the generated files by ./regevAES and ./dualAES
