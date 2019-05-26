
#define CLSCRYPTO_EXPORTS

#include "libsslmng.h"
#ifndef _AIX
#include "libmngErrno.h"
#endif

const int num_algorithms = 2;
// El metodo SHA1 compone una encriptacion bastante larga, y es un estandar
// El metodo MATRIX se basa en una matriz posicional aleatoria, y sera usado con UTF-8
// El metodo VIGENERE (s. XVI) es una matriz bidimensional basado en el alfabeto,
//    con desplazamientos en base a una palabra clave en cada una de sus filas.
//    No existe una relacion clara con el texto original, salvo en que conserva
//    su longitud. Debe ser utilizado solamente con ASCII.
const char *str_algorithms[] = { "MATRIX_ALG", "VIGENERE_ALG" };
enum algorithms { MATRIX_ALG, VIGENERE_ALG };

/*
#ifndef _POSIX_ARG_MAX
#define _POSIX_ARG_MAX 4096
#endif
#ifndef _POSIX_SSIZE_MAX
#define _POSIX_SSIZE_MAX 4096
#endif*/
//
//const char *m_ASCII_alphabet = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz0123456789!#$%&'()*+-./";
// Ejemplo con clave "Nyarlothotep":
/*
const char *str_vigenere[] =
{ "NÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLM",
  "yz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwx",
  "abcdefghijklmnñopqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZ",
  "rstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopq",
  "lmnñopqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijk",
  "opqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñ",
  "tuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrs",
  "hijklmnñopqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefg",
  "opqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñ",
  "tuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrs",
  "efghijklmnñopqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcd",
  "pqrstuvwxyz0123456789 !#$%&'()*+-./ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnño" };
*/
long cbl_length(char *sSource, size_t nSource)
{
       size_t offset = 0;
       for (; ((offset < (nSource-1)) && (sSource[offset] != 0x00)); offset++);
       if (sSource[offset] == 0x00) offset--;
       nSource = offset + 1;
       for (; ((nSource > 0) && ((sSource[offset] == 0x20) || (sSource[offset] == 0x00 ))); offset--, nSource--);

       return(nSource);
}

/*
*To convert 53 to the character 'S':
*char returnVal = hexToString('5', '3');
*/
char hexToAscii(char first, char second)
{
  char hex[5], *stop;
  hex[0] = '0';
  hex[1] = 'x';
  hex[2] = first;
  hex[3] = second;
  hex[4] = 0;

  return (char)strtol(hex, &stop, 16);
}

/*
//----------------------------------------------------------------------
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
};*/

clsCrypto::clsCrypto()
{
  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte
     integers on the stack as 64 bits of contigous salt material -
     ofcourse this only works if sizeof(int) >= 4 */
  // Para Vigenere
  //char bridge[4];
  m_vigenere_rows = 1;
  m_vigenere_chars = 0;

  // Alfabeto por defecto
#ifdef _AIX
  strcpy((char*)m_ASCII_alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$%()*+-.");
#else
  strcpy_s((char*)m_ASCII_alphabet, sizeof (m_ASCII_alphabet),"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$%()*+-.");
#endif
  m_vigenere_chars = strlen((char*)m_ASCII_alphabet);
  //
  /* Carga dinamica de la libreria "liberrmng.so" */
  //Carga_LibErrMNG();
  /*
  try {
  } catch(int e)
  {
    cobprintf((unsigned char*)"****EXCEPTION Nr. %d\n", e);
    exit(-1);
  }
  */

  m_lenMatrix = 0;
}

/*--------------------------------------------------------------------*\
 | SetParamVigenere                                                   |
 | ================                                                   |
 |                                                                    |
 | Establecer el alfabeto y la palabra clave que utilizara el         |
 | algoritmo VIGENERE_ALG.                                            |
 |                                                                    |
 | Parametros de entrada:                                             |
 |   - Alfabeto (opcional)                                            |
 |   - Longitud del alfabeto                                          |
 |   - Palabra clave                                                  |
 |   - Longitud de la palabra clave                                   |
 |                                                                    |
 | Parametros de salida:                                              |
 |   - Cantidad de filas de la matriz (igual a la longitud de la      |
 |     palabra clave).                                                |
 |                                                                    |
\*--------------------------------------------------------------------*/
long clsCrypto::SetParamVigenere(unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword)
{
   if ((lenAlphabet > 254) || ((lenAlphabet < 0))){

     return(_LIBSSLMNG_ERRCOD_001);
   }
   if (lenPassword < 6){

     return(_LIBSSLMNG_ERRCOD_002);
   }
   if (lenAlphabet > 0) {
     int i = 0;
     for (; i<lenAlphabet; i++) {
       if (i < lenAlphabet-1) {
         for (int j=i+1; j<lenAlphabet; j++) {
           if (sAlphabet[i] == sAlphabet[j]) {

             return(_LIBSSLMNG_ERRCOD_003);
           }
         }
         m_ASCII_alphabet[i] = sAlphabet[i];
       }
     }
     m_ASCII_alphabet[i] = 0x00;
     //strcpy((char*)m_ASCII_alphabet, (char*)sAlphabet);
   }
   m_arrayVigenere = new char*[lenPassword];

   for(int i=0; i<lenPassword; i++) {
      m_arrayVigenere[i] = new char[m_vigenere_chars];
      int idx=0, found = FALSE;
      for (; idx<m_vigenere_chars; idx++) {
        if (sPassword[i] == m_ASCII_alphabet[idx]) {
          found = TRUE;
          break;
        }
      }
      if (found == FALSE) {

        return(_LIBSSLMNG_ERRCOD_004);
      }
      int j = 0;
      for (int k=idx; k<m_vigenere_chars; k++) {
        m_arrayVigenere[i][j++] = m_ASCII_alphabet[k];
      }
      for (int k=0; k<idx; k++) {
        m_arrayVigenere[i][j++] = m_ASCII_alphabet[k];
      }
      //strcpy(m_arrayVigenere[i], m_ASCII_alphabet);
   }

   m_vigenere_rows = lenPassword;

   return ((long)m_vigenere_rows);
}

/*--------------------------------------------------------------------*\
 | GenerateRandomMatrix                                               |
 | ====================                                               |
 |                                                                    |
 | Generar una matriz posicional aleatoria de tamaño n para encriptar |
 | con el metodo MATRIX_ALG.                                          |
 |                                                                    |
 | Parametros de entrada:                                             |
 |   - Longitud de la matriz                                          |
 |                                                                    |
 | Parametros de salida:                                              |
 |   - Matriz en un string con posiciones formateadas con 4 digitos   |
 |   - Longitud de la matriz multiplicada por 4                       |
 |                                                                    |
\*--------------------------------------------------------------------*/
long clsCrypto::GenerateRandomMatrix(const int lenMatrix, unsigned char *sMatrix)
{
	if (lenMatrix > _POSIX_SSIZE_MAX) {

      m_lenMatrix = -1;
      return(_LIBSSLMNG_ERRCOD_005);
    }

    int number = 0, found = FALSE;

    m_lenMatrix = lenMatrix;

#ifdef _AIX
  srand (time(NULL));
#else
	srand (1000);
#endif

    for (int i=0; i<m_lenMatrix; i++) {
      do {
        found = FALSE;
        number = (int)(rand()%m_lenMatrix);
        for (int j=0; j<i; j++) {
          if (m_matrixInts[j] == number) {
            found=TRUE;
            break;
          }
        }
      } while (found == TRUE);
      m_matrixInts[i] = number;
    }
    // Componer el string con la matriz para COBOL
    unsigned char *myMatrix = (unsigned char*)malloc(m_lenMatrix * 4);
    unsigned char myBridge[5];

	strcpy((char*)myMatrix, "");
    for (long i=0; i<m_lenMatrix; i++) {
		sprintf((char*)myBridge, "%04d", m_matrixInts[i]);
		strcat((char*)myMatrix, (const char*)myBridge);
    }

    memcpy(sMatrix, myMatrix, m_lenMatrix * 4);

    return ((long)m_lenMatrix * 4);
}

/*--------------------------------------------------------------------*\
 | UseMatrix                                                          |
 | =========                                                          |
 |                                                                    |
 | Establecer la matriz con la que vamos a trabajar con el metodo     |
 | MATRIX_ALG.                                                        |
 |                                                                    |
 | NOTA: Esta funcion se utilizara cuando queramos reutilizar una     |
 | matriz generada previamente.                                       |
 |                                                                    |
 | Parametros de entrada:                                             |
 |   - Matriz en un string con posiciones formateadas con 4 digitos   |
 |   - Longitud del string                                            |
 |                                                                    |
 | Parametros de salida:                                              |
 |   - Longitud de la matriz (real)                                   |
 |                                                                    |
\*--------------------------------------------------------------------*/
long clsCrypto::UseMatrix(unsigned char *sMatrix, size_t lenMatrix)
{
	if (lenMatrix > _POSIX_SSIZE_MAX) {

      return(_LIBSSLMNG_ERRCOD_006);
    }

    unsigned char myBridge[5];
    int j = 0;

    for (int i=0; i<(int)lenMatrix; i++, j++) {
      myBridge[0] = sMatrix[i++];
      myBridge[1] = sMatrix[i++];
      myBridge[2] = sMatrix[i++];
      myBridge[3] = sMatrix[i];
      myBridge[4] = 0x00;
      m_matrixInts[j] = atoi((char*)myBridge);
    }
    m_lenMatrix = j;

    return ((long)(m_lenMatrix));
}

/*--------------------------------------------------------------------*\
 | Encrypt                                                            |
 | =======                                                            |
 |                                                                    |
 | Encriptar una cadena con el metodo indicado.                       |
 |                                                                    |
 | Parametros de entrada:                                             |
 |   - Algoritmo a utilizar                                           |
 |   - Longitud del string del algoritmo                              |
 |   - Texto a encriptar                                              |
 |   - Longitud del texto a encriptar                                 |
 |                                                                    |
 | Parametros de salida:                                              |
 |   - Campo que recibira el texto encriptado                         |
 |   - Capacidad del campo que recibira el texto encriptado           |
 |   - Longitud del texto encriptado                                  |
 |                                                                    |
\*--------------------------------------------------------------------*/
long clsCrypto::Encrypt(const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget)
{
    if (sAlgorithm == NULL) {

      return(_LIBSSLMNG_ERRCOD_007);
    }

    if ((sSource == NULL) || (lenSource < 1) ) {

      return(_LIBSSLMNG_ERRCOD_008);
    }

    if (lenTarget < 1) {

      return(_LIBSSLMNG_ERRCOD_009);
    }

	char myAlgorithm[128];
	memset(myAlgorithm, 0, sizeof(myAlgorithm));
	strncpy((char*)myAlgorithm, (char*)sAlgorithm, cbl_length((char*)sAlgorithm, lenAlgorithm));
    //char *myAlgorithm = _strndup((char*)sAlgorithm, cbl_length((char*)sAlgorithm, lenAlgorithm));
    bool swFound = FALSE;
    int idxAlgorithm = 0;
    for (; idxAlgorithm<num_algorithms; idxAlgorithm++) {
      if (strcmp(str_algorithms[idxAlgorithm], myAlgorithm) == 0) {
        //printf("Encontrado en elemento %d\n", idxAlgorithm);
        swFound = TRUE;
        break;
      }
    }
    if (swFound == FALSE) {

      return(_LIBSSLMNG_ERRCOD_010);
    }

    unsigned char *myTarget = (unsigned char*)malloc(_POSIX_ARG_MAX);
    unsigned char *mySource = (unsigned char*)malloc(_POSIX_ARG_MAX);

    //char *plaintext;
    int lenEncrypted = 0;
    size_t newLen = 0;

    switch (idxAlgorithm)
    {
      case MATRIX_ALG:
          if (m_lenMatrix == 0) {

            return(_LIBSSLMNG_ERRCOD_011);
          }
          if (( lenSource != m_lenMatrix) || (lenTarget != m_lenMatrix)) {

            return(_LIBSSLMNG_ERRCOD_022);
          }
		  strncpy((char*)mySource, (char*)sSource, m_lenMatrix);
          //mySource = (unsigned char*) _strndup((char*)sSource, m_lenMatrix);
          memset((char*)myTarget, 0x20, _POSIX_ARG_MAX);
          for (int idxOrigin=0, idxTarget=0; idxOrigin<m_lenMatrix; idxOrigin++) {
              idxTarget = m_matrixInts[idxOrigin];
              myTarget[idxTarget] = mySource[idxOrigin];
          }
          newLen = lenEncrypted = m_lenMatrix;
          break;
      case VIGENERE_ALG:
          if (m_vigenere_rows == 1) {

            return(_LIBSSLMNG_ERRCOD_012);
          }
          //size_t myLenSource = cbl_length((char*)sSource, lenSource);
          size_t myLenSource = lenSource;
          memset((char*)myTarget, 0x20, _POSIX_ARG_MAX);
		  strncpy((char*)mySource, (char*)sSource, myLenSource);
          //mySource = (unsigned char*) _strndup((char*)sSource, myLenSource);
          int i, j, k = 0;
          bool swFound = FALSE;
          for (i=0; i<(int)myLenSource; i++) { // Recorremos uno a uno los caracteres del campo origen
            swFound = FALSE;
            for (j=0; j<m_vigenere_chars; j++) { // Recorremos la matriz de caracteres Vigenere
              if (sSource[i] == m_ASCII_alphabet[j]) {
                myTarget[i] = m_arrayVigenere[k][j];
                swFound = TRUE;
                break;
              }
            }
            if (swFound == FALSE) { // Caracter no encontrado; se deja igual
              myTarget[i] = mySource[i];
            }
            k++;
            if (k >= m_vigenere_rows) k = 0;
          }
          newLen = lenEncrypted = myLenSource;
          break;
    }

    // Copy encryptation to destination
    memset((char*)sTarget, 0x00, lenTarget);
    if (newLen > lenTarget) {

      return(_LIBSSLMNG_ERRCOD_013);
    }
    else {
      //char sBridge[3];
      for (int i = 0; i < lenEncrypted; i++) {
          sTarget[i] = myTarget[i];
      }
      // Resto de la cadena encriptada a espacios, a partir del final
      for (long i=newLen; i < (int)lenTarget; i++) sTarget[i] = 0x20;

      return((long)newLen);
    }
}

/*--------------------------------------------------------------------*\
 | Decrypt                                                            |
 | =======                                                            |
 |                                                                    |
 | Desencriptar una cadena con el metodo indicado.                    |
 |                                                                    |
 | Parametros de entrada:                                             |
 |   - Algoritmo a utilizar                                           |
 |   - Longitud del string del algoritmo                              |
 |   - Texto encriptado                                               |
 |   - Longitud del texto encriptado                                  |
 |                                                                    |
 | Parametros de salida:                                              |
 |   - Campo que recibira el texto desencriptado                      |
 |   - Capacidad del campo que recibira el texto desencriptado        |
 |   - Longitud del texto desencriptado                               |
 |                                                                    |
\*--------------------------------------------------------------------*/
long clsCrypto::Decrypt(const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget)
{
    if (sAlgorithm == NULL) {

      return(_LIBSSLMNG_ERRCOD_014);
    }

    if ((sSource == NULL) || (lenSource < 1) ) {

      return(_LIBSSLMNG_ERRCOD_015);
    }

    if (lenTarget < 1) {

      return(_LIBSSLMNG_ERRCOD_016);
    }

    char myAlgorithm[128]; memset((char*)myAlgorithm, 0x00, sizeof(myAlgorithm));
	strncpy((char*)myAlgorithm, (char*)sAlgorithm, cbl_length((char*)sAlgorithm, lenAlgorithm));

    //char *myAlgorithm = _strndup((char*)sAlgorithm, cbl_length((char*)sAlgorithm, lenAlgorithm));
    bool swFound = FALSE;
    int idxAlgorithm = 0;
    for (; idxAlgorithm<num_algorithms; idxAlgorithm++) {
      if (strcmp(str_algorithms[idxAlgorithm], myAlgorithm) == 0) {
        //printf("Encontrado en elemento %d\n", idxAlgorithm);
        swFound = TRUE;
        break;
      }
    }
    if (swFound == FALSE) {

      return(_LIBSSLMNG_ERRCOD_017);
    }

	unsigned char *mySource = (unsigned char*)malloc(_POSIX_SSIZE_MAX);
	memset((char*)mySource, 0x20, _POSIX_SSIZE_MAX);

    switch (idxAlgorithm)
    {
      case MATRIX_ALG:
          if (( lenSource != m_lenMatrix) || (lenTarget != m_lenMatrix)) {

            return(_LIBSSLMNG_ERRCOD_022);
          }
          for (long i=0; i<(int)lenSource; i++)
          {
            mySource[i] = sSource[i];
            //temporal
            //printf("%02x ", mySource[i]);
          }
          break;
      case VIGENERE_ALG:
          if (m_vigenere_rows == 1) {

            return(_LIBSSLMNG_ERRCOD_018);
          }
          for (long i=0; i<(int)lenSource; i++)
          {
            mySource[i] = sSource[i];
            //temporal
            //printf("%02x ", mySource[i]);
          }
          break;
    }
    char *myTarget = (char*)malloc(_POSIX_SSIZE_MAX);

    int lenDecrypted = 0;
    switch (idxAlgorithm)
    {
      case MATRIX_ALG:
          if (m_lenMatrix == -1) {

            return(_LIBSSLMNG_ERRCOD_019);
          }
          memset((char*)myTarget, 0x20, _POSIX_ARG_MAX);

          for (int idxOrigin=0, idxTarget=0; idxOrigin<m_lenMatrix; idxOrigin++) {
              idxTarget = m_matrixInts[idxOrigin];
              myTarget[idxOrigin] = mySource[idxTarget];
          }
          lenDecrypted = m_lenMatrix;
          break;
      case VIGENERE_ALG:
          memset((char*)myTarget, 0x20, _POSIX_ARG_MAX);

          //temporal
          int i, j, k = 0;
          bool swFound = FALSE;
          for (i=0; i<(int)lenSource; i++) { // Recorremos uno a uno los caracteres del campo origen
            swFound = FALSE;
            for (j=0; j<m_vigenere_chars; j++) { // Recorremos la matriz de caracteres Vigenere
              if (mySource[i] == m_arrayVigenere[k][j]) {
                myTarget[i] = m_ASCII_alphabet[j];
                swFound = TRUE;
                break;
              }
            }
            if (swFound == FALSE) { // Caracter no encontrado; se deja igual
              myTarget[i] = mySource[i];
            }
            k++;
            if (k >= m_vigenere_rows) k = 0;
          }

          lenDecrypted = cbl_length((char*)mySource, lenSource);
          break;
    }


    // Copy encryptation to destination
    memset((char*)sTarget, 0x00, lenTarget);
    if (lenDecrypted > (int)lenTarget) {

      return(_LIBSSLMNG_ERRCOD_020);
    }
    else {
      strncpy((char*)sTarget, myTarget, lenDecrypted);
      return((long)lenDecrypted);
    }
}

clsCrypto::~clsCrypto(void)
{
    //if (myclsLibErrMNG != NULL) destroy( myclsLibErrMNG );
}

int main(int argc,  char** argv) {
   return 0;
}
#ifdef _AIX

//----------------------------------------------------------------------
// Wrapper COBOL
extern "C" {
  handleCrypto mngCryptoNew(){return(new clsCrypto());}
  long         mngSetParamVigenere(handleCrypto *hCrypto, unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword){ return ((*hCrypto)->SetParamVigenere(sAlphabet, lenAlphabet, sPassword, lenPassword));}
  long         mngGenerateMatrix(handleCrypto *hCrypto, const int lenMatrix, unsigned char *sMatrix){ return ((*hCrypto)->GenerateRandomMatrix(lenMatrix, sMatrix));}
  long         mngUseMatrix(handleCrypto *hCrypto, unsigned char*sMatrix, size_t lenMatrix){return ((*hCrypto)->UseMatrix(sMatrix, lenMatrix));}
  long         mngEncrypt(handleCrypto *hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget){return((*hCrypto)->Encrypt(sAlgorithm, lenAlgorithm, sSource, lenSource, sTarget, lenTarget));}
  long         mngDecrypt(handleCrypto *hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget){return((*hCrypto)->Decrypt(sAlgorithm, lenAlgorithm, sSource, lenSource, sTarget, lenTarget));}
  void         mngCryptoFree(handleCrypto *hCrypto){delete hCrypto; *hCrypto = NULL;}
} // of extern "C"
#else

//extern "C" {
//
//	CLSCRYPTO_API long test(unsigned char* sPassword, const int lenPassword)
//	{
//		strncpy((char*)sPassword, "hello", lenPassword);
//		return (long)1000;
//	}
//
//	CLSCRYPTO_API handleCrypto mngCryptoNew()
//	{
//		return(new clsCrypto());
//	}
//	CLSCRYPTO_API long mngSetParamVigenere(handleCrypto hCrypto, unsigned char *sAlphabet, const int lenAlphabet, unsigned char *sPassword, const int lenPassword)
//	{
//		return (hCrypto->SetParamVigenere(sAlphabet, lenAlphabet, sPassword, lenPassword));
//	}
//	CLSCRYPTO_API long mngGenerateMatrix(handleCrypto hCrypto, const int lenMatrix, unsigned char *sMatrix)
//	{
//		long result = (hCrypto->GenerateRandomMatrix(lenMatrix, sMatrix));
//		sMatrix[result] = 0x0;
//		return result;
//	}
//	CLSCRYPTO_API long mngUseMatrix(handleCrypto hCrypto, unsigned char*sMatrix, size_t lenMatrix)
//	{
//		return (hCrypto->UseMatrix(sMatrix, lenMatrix));
//	}
//	CLSCRYPTO_API long mngEncrypt(handleCrypto hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget)
//	{
//		long result = hCrypto->Encrypt(sAlgorithm, lenAlgorithm, sSource, lenSource, sTarget, lenTarget);
//		sTarget[result] = 0x0;
//		return (result);
//	}
//	CLSCRYPTO_API long mngDecrypt(handleCrypto hCrypto, const unsigned char *sAlgorithm, size_t lenAlgorithm, unsigned char *sSource, size_t lenSource, unsigned char *sTarget, size_t lenTarget)
//	{
//		long result = hCrypto->Decrypt(sAlgorithm, lenAlgorithm, sSource, lenSource, sTarget, lenTarget);
//		sTarget[result] = 0x0;
//		return (result);
//	}
//	CLSCRYPTO_API void mngCryptoFree(handleCrypto hCrypto)
//	{
//		delete hCrypto; hCrypto = NULL;
//	}
//}

#endif //_AIX
