using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace LightestNight.System.Encryption
{
    public static class Encryptor
    {
        public static async Task<EncryptedDataBlock> Encrypt(byte[] publicKey, string dataToEncrypt)
        {
            var (encryptedValue, aesKey, aesIv) = await SymmetricallyEncrypt(dataToEncrypt).ConfigureAwait(false);
            var hash = GenerateHash(Encoding.UTF8.GetBytes(encryptedValue));
            var digitalSignature = AsymmetricallyEncrypt(publicKey, hash);

            return new EncryptedDataBlock
            {
                EncryptedData = encryptedValue,
                DigitalSignature = digitalSignature,
                AesKey = Convert.ToBase64String(aesKey),
                InitialisationVector = Convert.ToBase64String(aesIv)
            };
        }

        private static async Task<(string EncryptedValue, byte[] AesKey, byte[] AesIv)> SymmetricallyEncrypt(
            string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(dataToEncrypt))
                throw new ArgumentNullException(nameof(dataToEncrypt));

            byte[] encrypted, aesKey, aesIv;
            using (var aesAlg = Aes.Create())
            {
                if (aesAlg == null)
                    throw new ApplicationException("Creating an instance of AES failed.");

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                await using (var msEncrypt = new MemoryStream())
                {
                    await using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        await using var swEncrypt = new StreamWriter(csEncrypt);
                        await swEncrypt.WriteAsync(dataToEncrypt).ConfigureAwait(false);
                    }

                    encrypted = msEncrypt.ToArray();
                }

                aesKey = aesAlg.Key;
                aesIv = aesAlg.IV;
            }

            return (Convert.ToBase64String(encrypted), aesKey, aesIv);
        }

        private static string AsymmetricallyEncrypt(byte[] publicKey, byte[] bytesToEncrypt)
        {
            var key = (RsaKeyParameters) PublicKeyFactory.CreateKey(publicKey);
            var rsaParameters = new RSAParameters
            {
                Modulus = key.Modulus.ToByteArrayUnsigned(),
                Exponent = key.Exponent.ToByteArrayUnsigned()
            };
            
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);
            var encrypted = rsa.Encrypt(bytesToEncrypt, false);
            return Convert.ToBase64String(encrypted);
        }

        private static byte[] GenerateHash(byte[] bytesToHash)
        {
            using var sha512 = new SHA512Managed();
            return sha512.ComputeHash(bytesToHash);
        }
    }
}