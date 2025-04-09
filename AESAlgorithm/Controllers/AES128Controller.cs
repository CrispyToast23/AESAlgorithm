using System.Text;
using AESAlgorithm.Common;
using AESAlgorithm.Services;
using Microsoft.AspNetCore.Mvc;

namespace AESAlgorithm.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AES128Controller : ControllerBase
    {
        AES128 AES128 { get; set; }

        public AES128Controller()
        {
            AES128 = new AES128();
        }

        [HttpGet(Name = "EncryptAES128")]
        public string EncryptAES128(string input, string key)
        {
            byte[] inputBytes = Helpers.ConvertStringToBytes(input);
            byte[] keyBytes = Helpers.ConvertStringToBytes(key);

            if (keyBytes.Length != 16)
                throw new ArgumentException("Key must be exactly 16 bytes for AES-128 encryption.");

            byte[] outputBytes = AES128.Encrypt(inputBytes, keyBytes);

            return Convert.ToBase64String(outputBytes);
        }
    }
}
