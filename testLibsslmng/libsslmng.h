
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
#endif // _AIX
#undef DEBUG
#define DEBUG 1
#ifndef TRUE
#define TRUE 1
#endif // TRUE
#ifndef FALSE
#define FALSE 0
#endif // FALSE

class clsCrypto;

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
extern "C"
{
	CLSCRYPTO_API handleCrypto mngCryptoNew();
	CLSCRYPTO_API long mngSetParamVigenere(handleCrypto *hCrypto, unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword);
	CLSCRYPTO_API long mngGenerateMatrix(handleCrypto *hCrypto, const int lenMatrix, unsigned char *sMatrix);
	CLSCRYPTO_API long mngUseMatrix(handleCrypto *hCrypto, unsigned char*sMatrix, size_t lenMatrix);
	CLSCRYPTO_API long mngEncrypt(handleCrypto *hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
	CLSCRYPTO_API long mngDecrypt(handleCrypto *hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget);
	CLSCRYPTO_API void mngCryptoFree(handleCrypto *hCrypto);
}

#endif
