using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace LightestNight.System.Encryption
{
    public static class Decryptor
    {
        public static async Task<TValue> Decrypt<TValue>(byte[] privateKey, EncryptedDataBlock dataBlock)
        {
            if (dataBlock == null)
                throw new ArgumentNullException(nameof(dataBlock));

            ValidateDigitalSignature(privateKey, dataBlock);

            var decryptedValue = await SymmetricallyDecrypt(Convert.FromBase64String(dataBlock.AesKey),
                    Convert.FromBase64String(dataBlock.InitialisationVector), dataBlock.EncryptedData)
                .ConfigureAwait(false);

            return JsonConvert.DeserializeObject<TValue>(decryptedValue);
        }

        private static void ValidateDigitalSignature(byte[] privateKey, EncryptedDataBlock dataBlock)
        {
            try
            {
                var decryptedDigitalSignature =
                    Convert.ToBase64String(AsymmetricallyDecrypt(privateKey, dataBlock.DigitalSignature));
                var hash = Convert.ToBase64String(GenerateHash(Encoding.UTF8.GetBytes(dataBlock.EncryptedData)));

                if (string.Compare(decryptedDigitalSignature, hash, StringComparison.OrdinalIgnoreCase) != 0)
                    throw new InvalidOperationException(
                        "The computed digital signature for the data block does not match the original digital signature.");
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException(
                    "There was a problem decrypting the data block. Potential data corruption or packet tampering has occurred.",
                    ex);
            }
        }

        private static async Task<string> SymmetricallyDecrypt(byte[] key, byte[] iv, string toDecrypt)
        {
            if (string.IsNullOrEmpty(toDecrypt))
                throw new ArgumentNullException(nameof(toDecrypt));

            using var aesAlg = Aes.Create();
            if (aesAlg == null)
                throw new ApplicationException("Creating an instance of AES failed.");

            aesAlg.Key = key;
            aesAlg.IV = iv;

            var cipherText = Convert.FromBase64String(toDecrypt);
            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            await using var msDecrypt = new MemoryStream(cipherText);
            await using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            return await srDecrypt.ReadToEndAsync().ConfigureAwait(false);
        }

        private static byte[] AsymmetricallyDecrypt(byte[] privateKey, string toDecrypt)
        {
            try
            {
                var key = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(privateKey);
                var rsaParameters2 = DotNetUtilities.ToRSAParameters(key);

                using var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters2);
                var decrypted = rsa.Decrypt(Convert.FromBase64String(toDecrypt), false);
                return decrypted;
            }
            catch (Exception ex)
            {
                throw new CryptographicException("An error occurred while decrypting the value. This is most likely due to an incorrect private key. See InnerException for more details.", ex);
            }
        }

        private static byte[] GenerateHash(byte[] bytesToHash)
        {
            using var sha512 = new SHA512Managed();
            return sha512.ComputeHash(bytesToHash);
        }
    }
}