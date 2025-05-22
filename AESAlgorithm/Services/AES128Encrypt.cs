using AESAlgorithm.Common;

namespace AESAlgorithm.Services
{
    public class AES128Encrypt : AESConstants
    {
        private byte[,] state = new byte[4, 4];

        public byte[] Encrypt(byte[] input, byte[] key)
        {
            byte[,] roundKeys = KeyExpansion(key);
            state = CopyInputToState(input, state);
            AddRoundKey(Helpers.GetRoundKey(roundKeys, 0));

            for (int round = 1; round <= 9; round++)
            {
                SubBytes();
                ShiftRows();
                MixColumns();
                AddRoundKey(Helpers.GetRoundKey(roundKeys, round));
            }

            SubBytes();
            ShiftRows();
            AddRoundKey(Helpers.GetRoundKey(roundKeys, 10));

            return GetStateAsByteArray(state);
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
            byte[,] tmp = new byte[4, 4];

            Array.Clear(tmp, 0, tmp.Length);

            for (int i = 0; i < 4; i++)
            {
                tmp[0, i] = (byte)(Helpers.GFMultiply(0x02, state[0, i]) ^ Helpers.GFMultiply(0x03, state[1, i]) ^ state[2, i] ^ state[3, i]);
                tmp[1, i] = (byte)(state[0, i] ^ Helpers.GFMultiply(0x02, state[1, i]) ^ Helpers.GFMultiply(0x03, state[2, i]) ^ state[3, i]);
                tmp[2, i] = (byte)(state[0, i] ^ state[1, i] ^ Helpers.GFMultiply(0x02, state[2, i]) ^ Helpers.GFMultiply(0x03, state[3, i]));
                tmp[3, i] = (byte)(Helpers.GFMultiply(0x03, state[0, i]) ^ state[1, i] ^ state[2, i] ^ Helpers.GFMultiply(0x02, state[3, i]));
            }

            state = tmp;
        }

        private void AddRoundKey(byte[,] roundKey)
        {
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    state[row, col] ^= roundKey[row, col];
                }
            }
        }
    }
}
