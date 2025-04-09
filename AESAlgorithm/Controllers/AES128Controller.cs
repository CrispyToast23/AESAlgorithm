using AESAlgorithm.Services;
using Microsoft.AspNetCore.Mvc;

namespace AESAlgorithm.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AES128Controller : ControllerBase
    {
        AES128 AES128 { get; set; }

        AES128Controller()
        {
            AES128 = new AES128();
        }

        [HttpGet(Name = "Encrypt")]
        public void Get()
        {
            AES128.Encrypt();
        }
    }
}
