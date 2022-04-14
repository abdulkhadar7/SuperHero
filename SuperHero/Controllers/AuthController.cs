using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SuperHeroAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public static User user = new User();
        

        [HttpPost("register")]
        public async Task<ActionResult> Register (UserDTO request)
        {
            CreatePasswordHash(request.password, out byte[] passwordHash, out byte[] passwordSalt);
            user.UserName = request.userName;
            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login (UserDTO request)
        {
            if(user.UserName != request.userName)
            {
                return BadRequest("User not Found");
            }

            if(!verifyPasswordHash(request.password,user.PasswordHash,user.PasswordSalt))
            {
                return BadRequest("Invalid Credentials");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash,out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private bool verifyPasswordHash(string password, byte[] passwordHash,byte[]passwordSalt)
        {
            using (var hmac= new HMACSHA512(passwordSalt))
            {
                var computeHash= hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual( passwordHash);
            }
        }

        private string CreateToken(User user)
        {
            List<Claim> claimsList = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName),
                new Claim(ClaimTypes.Role,"Admin"),


            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims:claimsList,
                signingCredentials:creds,
                expires:DateTime.Now.AddDays(1)
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

    }
}
