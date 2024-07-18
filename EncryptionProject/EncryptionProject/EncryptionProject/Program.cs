using System.Security.Cryptography;
using System.Text;
using System.Text.Json;


namespace EncryptionProject
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var payload = new Payload()
            {
                  transRef = "2024013123",
                  transactionDate = "09/07/2024",
                  debitAccount = "0501115310",
                  creditAccount = "0500592358",
                  currency = "NGN",
                  amount = "1000",
                  narration = "Testing",
                 beneficiaryName = "Samuel"
          };

           // {
             //   otp = "982752",
             //   accountNumber = "0501115310",
            //    phoneNumber = "08050451051"
          // };  



            var encryptionClass = new EncryptionHelper();

            

            var payloadString = encryptionClass.EncryptRequest(JsonSerializer.Serialize(payload));
            Console.WriteLine(payloadString);

            Console.WriteLine();
            Console.WriteLine();




            var postman = "EsxChzwQOeLJOU5xcECjtpolN7k3nl1oMy9Ea3Utd2juJeDibDd26114wSJg79P0ema1hBOjjITLlrYUThIjGBLqka/TW8DsyEExo/E4REajuC08QMUAquFTmAiWjFc6C1uq+9mUPX0NwmkcPHo4t0UxJo1vg9DTLYL8/gVcNGo=";

            var responseString = encryptionClass.DecryptResponse(postman);
            Console.WriteLine(responseString); Console.ReadKey();
        }
    }

    public class Payload()
    {
        public string transRef { get; set; }
        public string transactionDate { get; set; }
        public string debitAccount { get; set; }
        public string creditAccount { get; set; }
        public string currency { get; set; }
        public string narration { get; set; }
        public string beneficiaryName { get; set; } 
        public string amount { get; set; }
        public string accountNumber { get; set; }
        public string otp { get; set; }
        public string phoneNumber { get; set; }
    }

    public class EncryptionHelper
    {
        public string EncryptRequest(string clearText)
        {

            var message = "";
            string cipherText = "";
            try
            {
                //AuthKeyValue key = new AuthKeyValue();
                var key = GetKey();


                if (key != null)
                {
                    var plainText = clearText;
                    var saltValueBytes = Encoding.ASCII.GetBytes(key.SaltValue);
                    var password = new Rfc2898DeriveBytes(key.PassPhrase, saltValueBytes, key.PasswordIterations);
                    var keyBytes = password.GetBytes(key.Blocksize);
                    var symmetricKey = new RijndaelManaged();
                    var initVectorBytes = Encoding.ASCII.GetBytes(key.InitVector);
                    var encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
                    var memoryStream = new MemoryStream();
                    var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                    var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    var cipherTextBytes = memoryStream.ToArray();
                    memoryStream.Close();
                    cryptoStream.Close();
                    cipherText = Convert.ToBase64String(cipherTextBytes);
                    return cipherText;
                }
                else
                {
                    //logService.LogInfo($"Invalid route {route} was used");
                    message = "Invalid Keys";
                    return message;
                }
            }
            catch (Exception ex)
            {
                // logService.LogInfo(ex.Message);
                if (ex.Message.Contains("Padding is invalid"))
                {
                    message = "Invalid Keys";
                    return message;
                }
                if (ex.Message.Contains("The input is not a valid Base-64 string "))
                {
                    message = ex.Message;
                    return message;
                }
            }
            return cipherText;
        }

        public string DecryptResponse(string clearText)
        {

            var message = "";
            try
            {
                //AuthKeyValue key = new AuthKeyValue();
                var key = GetKey();
                if (key != null)
                {
                    var plainText = clearText;
                    var saltValueBytes = Encoding.ASCII.GetBytes(key.SaltValue);
                    var password = new Rfc2898DeriveBytes(key.PassPhrase, saltValueBytes, key.PasswordIterations);
                    var keyBytes = password.GetBytes(key.Blocksize);
                    var symmetricKey = new RijndaelManaged();
                    var initVectorBytes = Encoding.ASCII.GetBytes(key.InitVector);
                    var encryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
                    ICryptoTransform decryptor = encryptor;
                    byte[] buffer = Convert.FromBase64String(plainText);
                    using (MemoryStream ms = new MemoryStream(buffer))
                    {
                        using (CryptoStream cs = new CryptoStream((Stream)ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new StreamReader((Stream)cs))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
                else
                {
                    //logService.LogInfo($"Invalid route {route} was used");
                    message = "Invalid Keys";
                    return message;
                }
            }
            catch (Exception ex)
            {
                //logService.LogInfo(ex.Message);
                if (ex.Message.Contains("Padding is invalid"))
                {
                    message = "Invalid Keys";
                    return message;
                }
                if (ex.Message.Contains("The input is not a valid Base-64 string "))
                {
                    message = ex.Message;
                    return message;
                }
            }
            return "";
        }

        public KeyValue GetKey()
        {
            //var res = new KeyValue();
            var result = new KeyValue();

            result.PassPhrase = "Av2345fgbnhes78@#dn";
            result.SaltValue = "Dfcvb542*&sdcf87r";
            result.InitVector = "Mked098lasn34mg6";
            result.Blocksize = 32;
            result.PasswordIterations = 2;

            return result;
        }

        public class KeyValue
        {
            public string PassPhrase { get; set; }
            public string SaltValue { get; set; }
            public string InitVector { get; set; }
            public int PasswordIterations { get; set; }
            public int Blocksize { get; set; }
        }
    }

}
