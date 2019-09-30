using System;
using System.Web;
using System.Security.Cryptography;
using System.Text;
using System.Globalization;

namespace Shared_Access_Signature_token_Generator
{
    class Program
    {
        static void Main(string[] args)
        {
            string resourceUri = "";
            string key = ""; 
            string keyName = "";

            Console.WriteLine("enter the resource Uri");
            resourceUri = Console.ReadLine();

            Console.WriteLine("enter the key");
            key = Console.ReadLine();

            Console.WriteLine("enter the key name");
            keyName = Console.ReadLine();

            TimeSpan sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var expiry = Convert.ToString((int)sinceEpoch.TotalSeconds + 3600);
            string stringToSign = HttpUtility.UrlEncode(resourceUri) + "\n" + expiry;
            HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));

            var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
            var sasToken = String.Format(CultureInfo.InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}",
                HttpUtility.UrlEncode(resourceUri), HttpUtility.UrlEncode(signature), expiry, keyName);
            Console.WriteLine("please find the generating token:");
            Console.WriteLine(sasToken);
        }
    }
}
