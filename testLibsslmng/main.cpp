#include "libsslmng.h"

using namespace std;

int main()
{
	handleCrypto myHandle;
	unsigned char sEncrypted[1024];
	unsigned char sPlainText[1024];
	unsigned char sEncryptedMatrix[301];
	unsigned char sPlainTextMatrix[301];

	myHandle = mngCryptoNew();
	long result = mngSetParamVigenere(&myHandle, NULL, 0, (unsigned char*)"abraxas", strlen((char*)"abraxas"));

	long lenEncrypted = mngEncrypt(&myHandle, (unsigned char*)"VIGENERE_ALG", strlen((char*)"VIGENERE_ALG"), (unsigned char*)"texto plano", strlen((char*)"texto plano"), sEncrypted, sizeof(sEncrypted));

	cout << sEncrypted << endl;

	long lenDecrypted = mngDecrypt(&myHandle, (unsigned char*)"VIGENERE_ALG", strlen((char*)"VIGENERE_ALG"), sEncrypted, lenEncrypted, sPlainText, sizeof(sPlainText));

	cout << sPlainText << endl;

	unsigned char sMatrix[2048]; 
	strcpy((char*)sMatrix, "020502830168007100940102014500970256023601320098004200530264011700650291018901370083000002930077017802940109011901390056018501340036005501030011026701630104025301470012027702730197002402870231003301100281027900580057019900100286028002290170029801620136009902350129016402960003020200630278026802520035027602480093024901160086024602110080000802330120018802650213004900270066018100390212007900130176028802070251027001610149008900370158007300400155005000280018000402280232011100230108017100870135014102600243027101330263007602970029005100200227021701520282029200720238018201510105007400480216006700090269025501250223029502450014009600880289012602990082001602500206014200070144018301230148027400210215007501740025022201000201004401720052014601140193016702240262012202090186009201540070023700020001011301150101005401060241024200430204015901910225003200620196012100690208004600780038006801530173027202100060000600170041022001650175025400950221016601560091008101310128018402610143028500260022014002440138017900850045013002030180024700190090023000840064025900150059019201240190019401600290021901120157023401980034028402390030022602140118025800610240021801950187027502660169003102000177012701070047025701500005");
	long lenASCIIMatrix = 1200;

	long lenMatrix = mngUseMatrix(&myHandle, sMatrix, lenASCIIMatrix);
	cout << "mngUseMatrix=" << result << endl;

	strcpy((char*)sPlainTextMatrix, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

	memset((char*)sEncryptedMatrix, 0, 300);
	lenEncrypted = mngEncrypt(&myHandle, (unsigned char*)"MATRIX_ALG", strlen((char*)"MATRIX_ALG"), (unsigned char*)sPlainTextMatrix, lenMatrix, sEncryptedMatrix, lenMatrix);
	cout << sEncryptedMatrix << endl;

	memset((char*)sPlainTextMatrix, 0, 300);
	lenDecrypted = mngDecrypt(&myHandle, (unsigned char*)"MATRIX_ALG", strlen((char*)"MATRIX_ALG"), sEncryptedMatrix, lenMatrix, sPlainTextMatrix, lenMatrix);
	cout << sPlainTextMatrix << endl;

	memset((char*)sEncryptedMatrix, 0, 300);
	lenEncrypted = mngEncrypt(&myHandle, (unsigned char*)"MATRIX_ALG", strlen((char*)"MATRIX_ALG"), (unsigned char*)sPlainTextMatrix, lenMatrix, sEncryptedMatrix, lenMatrix);
	cout << sEncryptedMatrix << endl;

	memset((char*)sPlainTextMatrix, 0, 300);
	lenDecrypted = mngDecrypt(&myHandle, (unsigned char*)"MATRIX_ALG", strlen((char*)"MATRIX_ALG"), sEncryptedMatrix, lenMatrix, sPlainTextMatrix, lenMatrix);
	cout << sPlainTextMatrix << endl;

	return 0;
}
