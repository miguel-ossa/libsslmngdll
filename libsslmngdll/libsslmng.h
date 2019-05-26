
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
//#include <string>
#include <limits.h>
#include <time.h>
#include <string.h>
#ifdef _AIX
#include "../../include/libmngErrno.h" // POR QUÉ NO FUNCIONA CON -I EN EL MAKE????
#include "../../include/libmngTemplates.h" // POR QUÉ NO FUNCIONA CON -I EN EL MAKE????
#else
//#include "libmngErrno.h"
#endif // _AIX
#undef DEBUG
#define DEBUG 1
#ifndef TRUE
#define TRUE 1
#endif // TRUE
#ifndef FALSE
#define FALSE 0
#endif // FALSE

#ifndef _POSIX_ARG_MAX
#define _POSIX_ARG_MAX 4096
#endif
#ifndef _POSIX_SSIZE_MAX
#define _POSIX_SSIZE_MAX 4096
#endif

//class clsCrypto;
class clsCrypto {
private:

       // Matrix
	   int m_matrixInts[_POSIX_SSIZE_MAX];
       int m_lenMatrix;

       // Vigenere
       int m_vigenere_chars;
       int m_vigenere_rows;
       unsigned char m_ASCII_alphabet[255];
       char **m_arrayVigenere;

public:
       clsCrypto();
       long SetParamVigenere(unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword);
       long GenerateRandomMatrix(const int lenMatrix, unsigned char *sMatrix);
       long UseMatrix(unsigned char *sMatrix, size_t lenMatrix);
       long Encrypt(const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
       long Decrypt(const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
       ~clsCrypto(void);
};

typedef clsCrypto *handleCrypto;

long cbl_length(char *sSource, size_t nSource);
char hexToAscii(char first, char second);

#ifdef _AIX
// Wrapper COBOL
extern "C" {
  //
  handleCrypto mngCryptoNew();
  long         mngSetParamVigenere(handleCrypto *hCrypto, unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword);
  long         mngGenerateMatrix(handleCrypto *hCrypto, const int lenMatrix, unsigned char *sMatrix);
  long         mngUseMatrix(handleCrypto *hCrypto, unsigned char*sMatrix, size_t lenMatrix);
  long         mngEncrypt(handleCrypto *hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
  long         mngDecrypt(handleCrypto *hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
  void         mngCryptoFree(handleCrypto *hCrypto);
}
#else
#ifdef CLSCRYPTO_EXPORTS  
#define CLSCRYPTO_API __declspec(dllexport)   
#else  
#define CLSCRYPTO_API __declspec(dllimport)   
#endif  
/*extern "C"
{
	CLSCRYPTO_API long test(unsigned char* sPassword, const int lenPassword);
	CLSCRYPTO_API handleCrypto mngCryptoNew();
	CLSCRYPTO_API long mngSetParamVigenere(handleCrypto hCrypto, unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword);
	CLSCRYPTO_API long mngGenerateMatrix(handleCrypto hCrypto, const int lenMatrix, unsigned char *sMatrix);
	CLSCRYPTO_API long mngUseMatrix(handleCrypto hCrypto, unsigned char*sMatrix, size_t lenMatrix);
	CLSCRYPTO_API long mngEncrypt(handleCrypto hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
	CLSCRYPTO_API long mngDecrypt(handleCrypto hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
	CLSCRYPTO_API void mngCryptoFree(handleCrypto hCrypto);
}
*/
#endif
