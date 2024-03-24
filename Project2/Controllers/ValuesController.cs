using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data.Entity;
using System.Data.SQLite;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;



namespace Project2.Controllers
{   
    // Defines the route at the controller level
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        // Database filename for storing keys
        private static string DBFilename = "totally_not_my_privateKeys.db";

        // SQLite connection and command objects
        private static SQLiteConnection sqlite_conn;
        private static SQLiteCommand cmd = new SQLiteCommand();

        // Method to create a new RSA key, optionally expired
        private static void CreateKey(bool expiredKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 1024; // Sets the RSA key size to 1024 bits
                RSAParameters rsaParameters = rsa.ExportParameters(true);

                string pem = rsa.ExportRSAPrivateKeyPem(); // Exports the RSA private key as PEM

                DateTime expiry;
                long exp;
                if (expiredKey)
                    expiry = DateTime.Now.AddDays(-1); // Sets expiry to yesterday for an expired key
                else
                    expiry = DateTime.Now.AddDays(1); // Sets expiry to tomorrow for a valid key

                exp = new DateTimeOffset(expiry.ToUniversalTime()).ToUnixTimeSeconds(); // Converts expiry to Unix time

                // Inserts the new key into the database
                cmd.CommandText = "INSERT INTO keys ( key, exp) VALUES ( @key, @exp)";

                cmd.Parameters.Add(new SQLiteParameter("@kid", "NULL"));
                cmd.Parameters.Add(new SQLiteParameter("@key", pem));
                cmd.Parameters.Add(new SQLiteParameter("@exp", exp));   
                cmd.ExecuteNonQuery();
            }
        }

        // Constructor initializes the SQLite connection and creates the keys table
        public ValuesController()
        {
            // Establishes a new database connection
            sqlite_conn = new SQLiteConnection("Data Source = " + DBFilename + "; Version = 3; New = True; Compress = True; ");
            sqlite_conn.Open();

            cmd.Connection = sqlite_conn;
            // Creates the keys table if it does not exist
            cmd.CommandText = "CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)";
            cmd.ExecuteNonQuery();

            // Generates both an expired and a valid key
            CreateKey(true);
            CreateKey(false);
        }

        // Endpoint for authentication, optionally with an expired token
        [Route("/auth")]
        [HttpPost]
        public string Auth(string expired = "false")
        {
            SecurityToken token;

            long now = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds(); // Current time in Unix format

            // Selects a key based on the 'expired' parameter
            if (expired == "false")
                cmd.CommandText = "select * from keys where exp > @now limit 1"; // Selects a valid key
            else
                cmd.CommandText = "select * from keys where exp < @now limit 1"; // Selects an expired key

            cmd.Parameters.Add(new SQLiteParameter("@now", now));

            int kid = 0;
            string pem = "";
            int exp = 0;

            // Executes the query and reads the result
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                kid = reader.GetInt32(0);
                pem = reader.GetString(1);
                exp = reader.GetInt32(2);
            }

            // Creates a security token using the selected key
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(pem);
                RSAParameters rsaParameters = rsa.ExportParameters(true);
                RsaSecurityKey key = new RsaSecurityKey(rsaParameters) { KeyId = kid.ToString() };
                JsonWebKey jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);

                var td = new SecurityTokenDescriptor
                {
                    Expires = DateTime.Now.AddDays(1),
                    Issuer = "Baughman",
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha512Signature)
                };

                // Adjusts token validity for expired tokens
                if (expired == "true")
                {
                    td.NotBefore = DateTime.Now.AddDays(-2);
                    td.Expires = DateTime.Now.AddDays(-1);
                }
                var th = new JwtSecurityTokenHandler();
                token = th.CreateToken(td);
            }

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Endpoint to provide JSON Web Key Set (JWKS)
        [Route("/.well-known/jwks.json")]
        [HttpGet]
        public JsonWebKeySet Get()
        {
            int kid;
            string pem;
            int exp;

            JsonWebKeySet outJwks = new JsonWebKeySet();

            int now = int.Parse(new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString());
            cmd.CommandText = "select * from keys where exp > @now"; // Selects valid keys
            cmd.Parameters.Add(new SQLiteParameter("@now", now));

            // Reads and converts each key to JWKS format
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                using (RSA rsa = RSA.Create())
                {
                    kid = reader.GetInt32(0);
                    pem = reader.GetString(1);
                    exp = reader.GetInt32(2);

                    rsa.ImportFromPem(pem);
                    rsa.KeySize = 1024;

                    RSAParameters rsaParameters = rsa.ExportParameters(true);
                    RsaSecurityKey key = new RsaSecurityKey(rsaParameters) { KeyId = kid.ToString() };

                    JsonWebKey jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
                    outJwks.Keys.Add(jwk);
                }
            }

            return outJwks;
        }
    }
}
