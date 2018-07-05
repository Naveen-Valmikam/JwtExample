using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace JWTTokenExample
{
    class Program
    {
       
        static void Main(string[] args)
        {
            //Console.WriteLine("Enter a secret key");
            //var key = Console.ReadLine();
            //var token = CreateJWTTokenUsingSecretKey(key);

            var token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkU4NUJCODNFMDY5MEREREIwQjNDQjBDRDM5MDk5M0Y3MkRGOEFFOTQiLCJ0eXAiOiJKV1QifQ.eyJkZXZpZCI6IjZFM0ExNDI1LTVFRUMtNDcxNy04NENBLTQ4RDEzMURCQTZFQiIsImN1c3RpZCI6Ik0xMjM0NTYiLCJuYmYiOjE0ODg1MTIwMzMsImV4cCI6MTQ4OTExNjgzMywiaWF0IjoxNDg4NTEyMDMzLCJpc3MiOiJNTVNHIiwiYXVkIjoiUGF5d2l0aCJ9.TfXfroXdNaE_Au4K9sIS644PX_vRuQrSFRVcEWSxDgXhf5ebM-2qf6YFQbHEjE7gMohQlmaGebC5eL1BS69MGmMsOcoFWx2c5gdJZDgmmdnKfY_rMukyBqxDrIU6LYuSK9Fa3DekXge86pmGwYa6wjIu8qTz3H0fjJ_KZe01eRRdh6ji92vTSQhh4eo6mKCzreJY3c6Jtrn6N0iI-rbZIYr6YmipygelFKVkezn4tqH1svn4Tj48KrI72GrnzZmNQTn-1PvWXX4Brb29C9PCvwcYS3f_CX5VuivlXW0p5nsBQGlG_G52xCMC5RT19nMBhlYGdp76f7-hAfXtUonizg";
            //var token = GenerateJwtUsingX509Certificate();
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
                new Claim("devid","6E3A1425-5EEC-4717-84CA-48D131DBA6EB"),
                new Claim("custid","M123456")
            });

            tokenDescriptor.Issuer = "ABC";
            tokenDescriptor.Audience = "DEF";
         
            var now = DateTime.UtcNow;
            tokenDescriptor.IssuedAt = now;
            tokenDescriptor.Expires = now.AddDays(7);
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

            tokenDescriptor.Issuer = "ABC";
            tokenDescriptor.Audience = "DEF";
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
                validationParameters.ValidIssuer = "ABC";
                validationParameters.ValidAudience = "DEF";

                validationParameters.IssuerSigningKey = new X509SecurityKey(certificate);
                var validatedToken = tokenHandler.ReadToken(token);
                var claims = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
                Console.WriteLine(Environment.NewLine);
                foreach (var claim in claims.Claims)
                {
                    Console.WriteLine("Claim Type: " + claim.Type + "\tClaim Value: " + claim.Value);
                }

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
            var certThumbprint = "E85BB83E0690DDDB0B3CB0CD390993F72DF8AE94";            
            var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly);
            var certificates = certStore.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, true);
            if (certificates != null && certificates.Count > 0)
                return certificates[0];
            //if (certStore != null && certStore.Certificates != null && certStore.Certificates.Count > 0)
            //return certStore.Certificates[0];
            return new X509Certificate2();
        }

        private static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return Encoding.UTF8.GetBytes(str);
        }
    }
}
