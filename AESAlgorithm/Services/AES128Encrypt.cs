using AESAlgorithm.Common;

namespace AESAlgorithm.Services
{
    public class AES128Encrypt : AESConstants
    {
        private byte[,] state = new byte[4, 4];

        public byte[] Encrypt(byte[] input, byte[] key)
        {
            byte[,] roundKeys = KeyExpansion(key);
            CopyInputToState(input);
            AddRoundKey(GetRoundKey(roundKeys, 0));

            for (int round = 1; round <= 9; round++)
            {
                SubBytes();
                ShiftRows();
                MixColumns();
                AddRoundKey(GetRoundKey(roundKeys, round));
            }

            SubBytes();
            ShiftRows();
            AddRoundKey(GetRoundKey(roundKeys, 10));

            return GetStateAsByteArray();
        }

        private void CopyInputToState(byte[] input)
        {
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    state[row, col] = input[col * 4 + row];
                }
            }
        }

        private byte[] GetStateAsByteArray()
        {
            byte[] result = new byte[16];

            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    result[col * 4 + row] = state[row, col];
                }
            }

            return result;
        }

        public byte[,] GetRoundKey(byte[,] expandedKey, int round)
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

        private void SubBytes()
        {
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    byte currentByte = state[row, col];

                    int highNibble = (currentByte >> 4 & 0xF);
                    int lowNibble = (currentByte & 0xF);

                    state[row, col] = sBox[highNibble, lowNibble];
                }
            }
        }

        private void ShiftRows()
        {
            for (int row = 0; row < 4; row++)
            {
                byte[] shiftedRow = new byte[4];

                for (int col = 0; col < 4; col++)
                {
                    shiftedRow[(col + row) % 4] = state[row, col];
                }

                for (int col = 0; col < 4; col++)
                {
                    state[row, col] = shiftedRow[col];
                }
            }
        }

        private void MixColumns()
        {
            byte[] tempColumn = new byte[4];

            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    tempColumn[row] = state[row, col];
                }

                for (int row = 0; row < 4; row++)
                {
                    byte newValue = 0;

                    for (int k = 0; k < 4; k++)
                    {
                        newValue ^= Helpers.GFMultiply(tempColumn[k], mixColumnsMatrix[row, k]);
                    }

                    state[row, col] = newValue;
                }
            }
        }

        private void AddRoundKey(byte[,] roundKey)
        {
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    state[row, col] = (byte)(state[row, col] ^ roundKey[row, col]);
                }
            }
        }
    }
}
