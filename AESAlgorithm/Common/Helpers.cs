using System.Text;
using AESAlgorithm.Services;

namespace AESAlgorithm.Common
{
    public static class Helpers
    {
        public static byte GFMultiply(byte a, byte b)
        {
            byte p = 0;

            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hi_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if (hi_bit_set)
                {
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }

            return p;
        }

        public static byte[] RotateWord(byte[] currentWord)
        {
            int arrLength = currentWord.Length;

            for (int i = 0; i < arrLength / 2; i++)
            {
                byte temp = currentWord[i];
                currentWord[i] = currentWord[arrLength - i - 1];
                currentWord[arrLength - i - 1] = temp;
            }

            return currentWord;
        }

        public static byte[] SubWord(byte[] currentWord, byte[,] sBox)
        {
            for (int i = 0; i < 4; i++)
            {
                currentWord[i] = sBox[currentWord[i] >> 4, currentWord[i] & 0x0F];
            }

            return currentWord;
        }

        public static byte[] ConvertStringToBytes(string input)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            int paddingRequired = 16 - (inputBytes.Length % 16);
            if (paddingRequired != 16)
            {
                byte[] paddedInput = new byte[inputBytes.Length + paddingRequired];
                Array.Copy(inputBytes, paddedInput, inputBytes.Length);

                for (int i = 0; i < paddingRequired; i++)
                {
                    paddedInput[inputBytes.Length + i] = 0x00;
                }

                return paddedInput;
            }

            return inputBytes;
        }

        public static byte[,] GetRoundKey(byte[,] expandedKey, int round)
        {
            byte[,] roundKey = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    roundKey[i, j] = expandedKey[j, (round * 4) + i];
                }
            }

            return roundKey;
        }
    }
}
