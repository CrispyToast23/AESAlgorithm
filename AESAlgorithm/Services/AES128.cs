using AESAlgorithm.Common;

namespace AESAlgorithm.Services
{
    public class AES128
    {
        public const int Nb = 4;
        public const int Nk = 4;
        public const int Nr = 10;

        private byte[,] state = new byte[4, 4];

        private static readonly byte[] Rcon =
        [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        ];

        private static readonly byte[,] mixColumnsMatrix = new byte[4, 4]
        {
            { 0x02, 0x03, 0x01, 0x01 },
            { 0x01, 0x02, 0x03, 0x01 },
            { 0x01, 0x01, 0x02, 0x03 },
            { 0x03, 0x01, 0x01, 0x02 }
        };

        private readonly byte[,] sBox = new byte[16, 16]
        {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa8, 0x51, 0xa3 },
            { 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c },
            { 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0x94, 0x73, 0x60, 0x81 },
            { 0x4f, 0x61, 0x37, 0x35, 0x4a, 0x4e, 0x4c, 0x6a, 0x72, 0x10, 0x2e, 0x20, 0x6e, 0x16, 0x2f, 0x0f },
            { 0x5d, 0x2b, 0x7e, 0x9a, 0x51, 0x56, 0x33, 0x39, 0x50, 0x2d, 0x29, 0x59, 0x0b, 0x69, 0x71, 0x31 },
            { 0x51, 0x62, 0x9d, 0x61, 0x67, 0x30, 0x98, 0x5f, 0x2c, 0x38, 0x94, 0x6b, 0x35, 0x0a, 0x4c, 0x49 },
            { 0x90, 0x81, 0x9f, 0x8c, 0x47, 0x58, 0x6d, 0x50, 0x62, 0x77, 0xb6, 0x2a, 0x7d, 0xe0, 0x63, 0x48 },
            { 0x85, 0x56, 0x53, 0x74, 0x57, 0x43, 0x35, 0x13, 0x65, 0x64, 0x59, 0x8b, 0x7b, 0x6e, 0x27, 0x72 },
            { 0x6f, 0x93, 0x7c, 0x8c, 0x2d, 0x3b, 0x5c, 0x76, 0x55, 0x6b, 0xa9, 0x80, 0x37, 0xa8, 0x5d, 0x3d },
            { 0x65, 0x11, 0x6d, 0x4c, 0x4e, 0x54, 0x7f, 0x59, 0x2b, 0x42, 0x56, 0xa0, 0x4d, 0x28, 0x1f, 0x56 },
            { 0xc4, 0xd1, 0x78, 0xf2, 0x65, 0x2a, 0x17, 0x7a, 0x13, 0x68, 0x75, 0x33, 0x89, 0xd2, 0x75, 0x0e },
            { 0x53, 0x87, 0x98, 0x58, 0x6e, 0x45, 0xc5, 0x89, 0x83, 0x58, 0x1d, 0x0d, 0x8e, 0x75, 0x29, 0x1e },
            { 0xd8, 0x52, 0x7a, 0x52, 0x79, 0x0f, 0x47, 0x57, 0x52, 0x85, 0x79, 0x53, 0xa2, 0xd4, 0x90, 0x0f },
            { 0x2e, 0x3b, 0x9b, 0x3f, 0x69, 0x94, 0x11, 0x8b, 0x5a, 0x4f, 0x30, 0xa6, 0x34, 0x4c, 0x6a, 0x81 },
            { 0x57, 0x9d, 0x59, 0x2f, 0x68, 0x14, 0xa5, 0x8a, 0x6b, 0x23, 0xb9, 0x32, 0xa7, 0x73, 0xd3, 0x92 }
        };

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
                    roundKey[i, j] = expandedKey[(round * 4) + i, j];
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

        private byte[,] KeyExpansion(byte[] key)
        {
            byte[,] expandedKey = new byte[4, 44];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    expandedKey[j, i] = key[(i * 4) + j];
                }
            }

            for (int i = 4; i < 44; i++)
            {
                byte[] temp = new byte[4];

                temp[0] = expandedKey[0, i - 1];
                temp[1] = expandedKey[1, i - 1];
                temp[2] = expandedKey[2, i - 1];
                temp[3] = expandedKey[3, i - 1];

                if (i % 4 == 0)
                {
                    temp = Helpers.RotateWord(temp);
                    temp = Helpers.SubWord(temp, sBox);
                    temp[0] ^= Rcon[i / 4];
                }

                expandedKey[0, i] = (byte)(expandedKey[0, i - 4] ^ temp[0]);
                expandedKey[1, i] = (byte)(expandedKey[1, i - 4] ^ temp[1]);
                expandedKey[2, i] = (byte)(expandedKey[2, i - 4] ^ temp[2]);
                expandedKey[3, i] = (byte)(expandedKey[3, i - 4] ^ temp[3]);
            }

            return expandedKey;
        }
    }
}
