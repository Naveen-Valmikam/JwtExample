using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTTokenExample
{
    class Program
    {
        static void Main(string[] args)
        {
            //Console.WriteLine("Enter a secret key");
            //var key = Console.ReadLine();
            //var token = CreateJWTTokenUsingSecretKey(key);            

            var token = GenerateJwtUsingX509Certificate();

            Console.WriteLine("JWT Token : " + token);
            var isTokenValid = ValidateToken(token);
            if(isTokenValid)
                Console.WriteLine(Environment.NewLine + "JWT Token Validated Successfully");
            else
                Console.WriteLine(Environment.NewLine + "JWT Token has been altered with.");
            Console.ReadLine();
        }

        public static string GenerateJwtUsingX509Certificate()
        {
            // Get the certificate for signing the JWT
            var certificate = GetCertificate();
            if (certificate == null)
                return "Invalid certificate or no certificate is loaded.";

            var securityKey = new X509SecurityKey(certificate);

            // Build the JWT claims                        
            var tokenDescriptor = new SecurityTokenDescriptor();

            var subject = new ClaimsIdentity(new Claim[]
            {
                new Claim("Deviceid","6E3A1425-5EEC-4717-84CA-48D131DBA6EB"),
                new Claim("CustomerId","M123456")
            });

            tokenDescriptor.Issuer = "MMSG";
            tokenDescriptor.Audience = "Paywith";
            var now = DateTime.UtcNow;
            tokenDescriptor.IssuedAt = now;
            tokenDescriptor.Expires = now.AddMinutes(2);
            tokenDescriptor.Subject = subject;
            tokenDescriptor.SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);        
                
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateJwtUsingSharedKey(string secretKey)
        {
            var securityKey = new SymmetricSecurityKey(GetBytes(secretKey));            
            var tokenHandler = new JwtSecurityTokenHandler();            
            var tokenDescriptor = new SecurityTokenDescriptor();
            
            var subject = new ClaimsIdentity(new Claim[]
            {
                new Claim("Deviceid","6E3A1425-5EEC-4717-84CA-48D131DBA6EB"),
                new Claim("CustomerId","M123456")
            });

            tokenDescriptor.Issuer = "MMSG";
            tokenDescriptor.Audience = "Paywith";
            var now = DateTime.UtcNow;
            tokenDescriptor.IssuedAt = now;
            tokenDescriptor.Expires = now.AddMinutes(2);
            tokenDescriptor.Subject = subject;
            tokenDescriptor.SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static bool ValidateToken(string token)
        {
            bool isValidToken = false;

            try
            {
                // get the certificate and its public key

                var certificate = GetCertificate();
                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters();
                validationParameters.ValidIssuer = "MMSG";
                validationParameters.ValidAudience = "Paywith";

                validationParameters.IssuerSigningKey = new X509SecurityKey(certificate);
                var validatedToken = tokenHandler.ReadToken(token);
                var claims = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
                isValidToken = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(Environment.NewLine + "Token Validation Failed: " + ex.Message);
                
            }
            return isValidToken;
        }

        private static X509Certificate2 GetCertificate()
        {
            var certThumbprint = "B219048772135ECAA97AD1700C090853AD803148";
            var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly);
            var certificates = certStore.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, true);
            if (certificates != null && certificates.Count > 0)
                return certificates[0];

            return new X509Certificate2();
        }

        private static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }
    }
}
