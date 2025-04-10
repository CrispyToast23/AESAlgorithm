using AESAlgorithm.Common;

namespace AESAlgorithm.Services
{
    public class AES128Decrypt : AESConstants
    {
        private byte[,] state = new byte[4, 4];

        public byte[] Decrypt(byte[] input, byte[] key)
        {
            byte[,] roundKeys = KeyExpansion(key);
            state = CopyInputToState(input, state);

            RemoveRoundKey(GetRoundKey(roundKeys, 10));
            InvShiftRows();
            InvSubBytes();

            for (int round = 9; round >= 1; round--)
            {
                RemoveRoundKey(GetRoundKey(roundKeys, round));
                InvMixColumns();
                InvShiftRows();
                InvSubBytes();
            }

            RemoveRoundKey(GetRoundKey(roundKeys, 0));

            return GetStateAsByteArray(state);
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

        private void InvSubBytes()
        {
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    byte currentByte = state[row, col];

                    int highNibble = (currentByte >> 4 & 0xF);
                    int lowNibble = (currentByte & 0xF);

                    state[row, col] = invSBox[highNibble, lowNibble];
                }
            }
        }

        private void InvShiftRows()
        {
            for (int row = 0; row < 4; row++)
            {
                byte[] shiftedRow = new byte[4];

                for (int col = 0; col < 4; col++)
                {
                    shiftedRow[(col - row + 4) % 4] = state[row, col];
                }

                for (int col = 0; col < 4; col++)
                {
                    state[row, col] = shiftedRow[col];
                }
            }
        }

        private void InvMixColumns()
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

                    for (int i = 0; i < 4; i++)
                    {
                        newValue ^= Helpers.GFMultiply(tempColumn[i], invMixColumnsMatrix[row, i]);
                    }

                    state[row, col] = newValue;
                }
            }
        }

        private void RemoveRoundKey(byte[,] roundKey)
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
