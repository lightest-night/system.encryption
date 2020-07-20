using System.Threading.Tasks;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace LightestNight.System.Encryption.Tests
{
    public class EncryptorTests
    {
        [Fact]
        public async Task ShouldEncryptSimpleDataWithGivenKeySuccessfully()
        {
            // Arrange
            const string data = "Test Data";
            var publicKey = KeyFactory.GenerateKeyPair().PublicKey;
            
            // Act
            var result = await Encryptor.Encrypt(publicKey, data);
            
            // Assert
            result.EncryptedData.ShouldNotBeNull();
            result.EncryptedData.ShouldNotBe(data);
        }

        [Fact]
        public async Task ShouldEncryptComplexDataWithGivenKeySuccessfully()
        {
            // Arrange
            var data = new TestObject
            {
                Foo = "Foo",
                Bar = long.MaxValue,
                List = {"String1", "String2", "String3"}
            };
            var publicKey = KeyFactory.GenerateKeyPair().PublicKey;
            
            // Act
            var result = await Encryptor.Encrypt(publicKey, await Task.Factory.StartNew(() => JsonConvert.SerializeObject(data)));
            
            // Assert
            result.EncryptedData.ShouldNotBeNullOrEmpty();
        }
    }
}