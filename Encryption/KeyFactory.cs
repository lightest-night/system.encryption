using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace LightestNight.System.Encryption
{
    public delegate (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair();
    
    public static class KeyFactory
    {
        private const int KeyStrength = 4096;

        public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            var randomGenerator = new CryptoApiRandomGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(randomGenerator), KeyStrength));

            var keys = rsaKeyPairGenerator.GenerateKeyPair();
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private);
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public);

            var publicKey = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var privateKey = privateKeyInfo.ToAsn1Object().GetDerEncoded();

            return (publicKey, privateKey);
        }
    }
}