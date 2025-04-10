using System.Text;
using AESAlgorithm.Services;

namespace AESAlgorithm.Common
{
    public static class Helpers
    {
        public static byte GFMultiply(byte currentByte, byte fixedByte)
        {
            byte result = 0;
            byte tempFixedByte = fixedByte;

            for (int i = 7; i >= 0; i--)
            {
                if ((currentByte & 0x80) != 0)
                {
                    result ^= tempFixedByte;
                }

                currentByte <<= 1;
                if ((currentByte & 0x80) != 0)
                {
                    currentByte ^= 0x1B;
                }

                tempFixedByte <<= 1;
                if ((tempFixedByte & 0x100) != 0)
                {
                    tempFixedByte ^= 0x1B;
                }
            }

            return result;
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
    }
}
