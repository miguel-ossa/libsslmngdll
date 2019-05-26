using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace testlibsslCSharp
{
    class Program
    {
        [DllImport("libsslmngdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr mngCryptoNew();
        [DllImport("libsslmngdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr mngSetParamVigenere(IntPtr hCrypto, byte[] bAlphabet, IntPtr lenAlphabet, byte[] bPassword, IntPtr lenPassword);
        [DllImport("libsslmngdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr mngEncrypt(IntPtr hCrypto, byte[] sAlgorithm, IntPtr lenAlgorithm, byte[] sSource, IntPtr lenSource, byte[] sTarget, IntPtr lenTarget);
        [DllImport("libsslmngdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr mngDecrypt(IntPtr hCrypto, byte[] sAlgorithm, IntPtr lenAlgorithm, byte[] sSource, IntPtr lenSource, byte[] sTarget, IntPtr lenTarget);
        [DllImport("libsslmngdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void mngCryptoFree(IntPtr hCrypto);
        [DllImport("libsslmngdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr mngUseMatrix(IntPtr hCrypto, byte[] sMatrix, IntPtr lenMatrix);


        [DllImport("libsslmngdll.dll", CallingConvention=CallingConvention.Cdecl)]
        public static extern UInt32 test([In, Out] byte[] sPassword, UInt32 lenPassword);

        static void Main(string[] args)
        {
            string sAlphabet = "";
            byte[] byteAlphabet = Encoding.UTF8.GetBytes(sAlphabet);
            IntPtr lenAlphabet = (IntPtr)sAlphabet.Length;

            string sPassword = "abraxas";
            byte[] bytePassword = Encoding.UTF8.GetBytes(sPassword);
            IntPtr lenPassword = (IntPtr)sPassword.Length;
            
            string sSource = "Texto a encriptar";
            byte[] byteSource = Encoding.UTF8.GetBytes(sSource);
            IntPtr lenSource = (IntPtr)sSource.Length;
            
            string sTarget = new string('*', 1024);
            byte[] byteTarget = Encoding.UTF8.GetBytes(sTarget);
            IntPtr lenTarget = (IntPtr)sTarget.Length;

            IntPtr myCrypt = mngCryptoNew();
            IntPtr myResult = mngSetParamVigenere(myCrypt, byteAlphabet, lenAlphabet, bytePassword, lenPassword);
            Console.WriteLine("mngSetParamVigenere Result = " + myResult);
            string sAlgorithm = "VIGENERE_ALG";
            byte[] byteAlgorithm = Encoding.UTF8.GetBytes(sAlgorithm);
            IntPtr lenAlgorithm = (IntPtr)sAlgorithm.Length;

            myResult = mngEncrypt(myCrypt, byteAlgorithm, lenAlgorithm, byteSource, lenSource, byteTarget, lenTarget);

            Console.WriteLine("mngEncrypt Result = " + myResult);
            Console.WriteLine("byteTarget=" + Encoding.Default.GetString(byteTarget));

            string sEncrypted = Encoding.Default.GetString(byteTarget);
            byte[] byteEncrypted = Encoding.UTF8.GetBytes(sEncrypted);

            myResult = mngDecrypt(myCrypt, byteAlgorithm, lenAlgorithm, byteEncrypted, myResult, byteTarget, lenTarget);

            Console.WriteLine("mngDecrypt Result = " + myResult);
            Console.WriteLine("byteTarget=" + Encoding.Default.GetString(byteTarget));

            string sMatrix = "020502830168007100940102014500970256023601320098004200530264011700650291018901370083000002930077017802940109011901390056018501340036005501030011026701630104025301470012027702730197002402870231003301100281027900580057019900100286028002290170029801620136009902350129016402960003020200630278026802520035027602480093024901160086024602110080000802330120018802650213004900270066018100390212007900130176028802070251027001610149008900370158007300400155005000280018000402280232011100230108017100870135014102600243027101330263007602970029005100200227021701520282029200720238018201510105007400480216006700090269025501250223029502450014009600880289012602990082001602500206014200070144018301230148027400210215007501740025022201000201004401720052014601140193016702240262012202090186009201540070023700020001011301150101005401060241024200430204015901910225003200620196012100690208004600780038006801530173027202100060000600170041022001650175025400950221016601560091008101310128018402610143028500260022014002440138017900850045013002030180024700190090023000840064025900150059019201240190019401600290021901120157023401980034028402390030022602140118025800610240021801950187027502660169003102000177012701070047025701500005";
            byte[] byteMatrix = Encoding.UTF8.GetBytes(sMatrix);
            IntPtr lenMatrix = (IntPtr)sMatrix.Length;

            // ===========
            // M A T R I X
            // ===========
            myResult = mngUseMatrix(myCrypt, byteMatrix, lenMatrix);
            // Si la matrix que le pasamos mide 1200, el resultado debe ser 300
            // 300 es el tamaño de todos los textos que encriptemos/desencriptemos
            // en adelante con este metodo
            Console.WriteLine("mngUseMatrix Result = " + myResult);

            string sPlainTextMatrix = "Вы можете вернуть или поменять вещи  в магазинах, которые находятся в стране, где была осуществлена первоначальная покупка                                                                           ";
            byte[] bytePlainTextMatrix = Encoding.UTF8.GetBytes(sPlainTextMatrix);
            IntPtr lenPlainTextMatrix = (IntPtr)300;
            string sTargetMatrix = new string('*', 300);
            byte[] byteTargetMatrix = Encoding.UTF8.GetBytes(sTargetMatrix);
            IntPtr lenTargetMatrix = (IntPtr)sTargetMatrix.Length;
            string sMatrixAlgorithm = "MATRIX_ALG";
            byte[] byteMatrixAlgorithm = Encoding.UTF8.GetBytes(sMatrixAlgorithm);
            IntPtr lenMatrixAlgorithm = (IntPtr)sMatrixAlgorithm.Length;

            myResult = mngEncrypt(myCrypt, byteMatrixAlgorithm, lenMatrixAlgorithm, bytePlainTextMatrix, lenPlainTextMatrix, byteTargetMatrix, lenTargetMatrix);

            Console.WriteLine("mngEncrypt Result = " + myResult);
            Console.WriteLine("byteTarget=" + Encoding.Default.GetString(byteTargetMatrix));

            string sDecryptedMatrix = new string('*', 300);
            byte[] byteDecryptedMatrix = Encoding.UTF8.GetBytes(sDecryptedMatrix);
            IntPtr lenDecryptedMatrix = (IntPtr)sDecryptedMatrix.Length;

            myResult = mngDecrypt(myCrypt, byteMatrixAlgorithm, lenMatrixAlgorithm, byteTargetMatrix, myResult, byteDecryptedMatrix, lenDecryptedMatrix);

            Console.WriteLine("mngDecrypt Result = " + myResult);
            Console.WriteLine("Decrypted Matrix=" + Encoding.Default.GetString(byteDecryptedMatrix));

            if (byteDecryptedMatrix.SequenceEqual(bytePlainTextMatrix))
            {
                Console.WriteLine("Encrypt/Decrypt OK");
            }
            else
            {
                Console.WriteLine("Encrypt/Decrypt ERROR");
            }

            mngCryptoFree(myCrypt);
            Console.WriteLine("That's all folks");

        }
    }
}
