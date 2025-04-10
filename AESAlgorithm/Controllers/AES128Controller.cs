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
        public string EncryptAES128(string input, string key)
        {
            AES128Encrypt AES128Encrypt = new();

            byte[] inputBytes = Helpers.ConvertStringToBytes(input);
            byte[] keyBytes = Helpers.ConvertStringToBytes(key);

            //byte[] inputBytes = [0x32, 0x88, 0x31, 0xe0, 0xc0, 0xc7, 0x2b, 0x2b, 0x9f, 0x23, 0xa9, 0x7c, 0xa6, 0x94, 0x6a, 0x8f];
            //byte[] keyBytes = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x75, 0x46, 0x11, 0x94, 0x31];

            //var t0 = new[] { inputBytes[0], inputBytes[1], inputBytes[2], inputBytes[3] };

            //var t1 =  Helpers.RotateWord(t0);
            //var t2 = Helpers.RotateWord(t1);

            if (keyBytes.Length != 16)
                throw new ArgumentException("Key must be exactly 16 bytes for AES-128 encryption.");

            byte[] outputBytes = AES128Encrypt.Encrypt(inputBytes, keyBytes);

            return Convert.ToBase64String(outputBytes);
        }

        [HttpGet("decrypt")]
        public string DecryptAES128(string input, string key)
        {
            AES128Decrypt AES128Decrypt = new();

            byte[] inputBytes = Convert.FromBase64String(input);
            byte[] keyBytes = Helpers.ConvertStringToBytes(key);

            //keyBytes = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x75, 0x46, 0x11, 0x94, 0x31];

            if (keyBytes.Length != 16)
                throw new ArgumentException("Key must be exactly 16 bytes for AES-128 decryption.");

            byte[] outputBytes = AES128Decrypt.Decrypt(inputBytes, keyBytes);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }
    }
}
