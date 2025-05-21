using System.Text;
using AESAlgorithm.Common;
using AESAlgorithm.Services;
using Microsoft.AspNetCore.Mvc;

namespace AESAlgorithm.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AES128Controller : ControllerBase
    {
        [HttpGet("encrypt")]
        public string EncryptAES128(string message, string key)
        {
            AES128Encrypt AES128Encrypt = new();

            byte[] bMessage = Encoding.ASCII.GetBytes(message);
            byte[] bKey = Encoding.ASCII.GetBytes(key);

            if (bKey.Length != 16)
                throw new Exception("The given Key is not the correct length");

            int padding = 16 - (bMessage.Length % 16);
            if (padding != 0)
            {
                Array.Resize(ref bMessage, bMessage.Length + padding);
                for (int i = bMessage.Length - padding; i < bMessage.Length; i++)
                {
                    bMessage[i] = (byte)padding;
                }
            }

            byte[] result = new byte[bMessage.Length];

            for (int i = 0; i < bMessage.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(bMessage, i, block, 0, 16);

                byte[] encryptedBlock = AES128Encrypt.Encrypt(block, bKey);
                Array.Copy(encryptedBlock, 0, result, i, 16);
            }

            return Convert.ToBase64String(result);
        }

        [HttpGet("decrypt")]
        public string DecryptAES128(string message, string key)
        {
            AES128Decrypt AES128Decrypt = new();

            byte[] bMessage = Convert.FromBase64String(message);
            byte[] bKey = Encoding.ASCII.GetBytes(key);

            if (bMessage.Length %16 != 0)
                throw new Exception("The given Message is not a multiple of 16!");
            if (bKey.Length != 16)
                throw new Exception("The given Key is not 16 Byte long!");
            byte[] result = new byte[bMessage.Length];

            for (int i = 0; i < bMessage.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(bMessage, i, block, 0, 16);

                byte[] decryptedBlock = AES128Decrypt.Decrypt(block, bKey);
                Array.Copy(decryptedBlock, 0, result, i, 16);
            }

            int padding = result[result.Length - 1];
            if (padding <= 0 || padding > 16)
                throw new Exception("Invalid padding!");

            for (int i = result.Length - padding; i < result.Length; i++)
            {
                if (result[i] != padding)
                    throw new Exception("Invalid padding content!");
            }

            byte[] unpaddedResult = new byte[result.Length - padding];
            Array.Copy(result, 0, unpaddedResult, 0, unpaddedResult.Length);

            string decrypted = Encoding.ASCII.GetString(unpaddedResult);
            return decrypted;
        }
    }
}
