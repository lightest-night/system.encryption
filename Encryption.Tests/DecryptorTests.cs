using System;
using System.Threading.Tasks;
using ExpectedObjects;
using Newtonsoft.Json;
using Shouldly;
using Xunit;

namespace LightestNight.System.Encryption.Tests
{
    public class DecryptorTests
    {
        private readonly JsonSerializerSettings _serializerSettings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };

        public DecryptorTests()
        {
            _serializerSettings.Converters.Insert(0, new JsonPrimitiveConverter());
        }

        [Fact]
        public async Task ShouldDecryptSimpleDataSuccessfully()
        {
            // Arrange
            var (publicKey, privateKey) = KeyFactory.GenerateKeyPair();
            const string testData = "Test Data";
            var dataBlock = await Encryptor.Encrypt(publicKey, JsonConvert.SerializeObject(testData, _serializerSettings));
            
            // Act
            var result = await Decryptor.Decrypt<string>(privateKey, dataBlock);
            
            // Assert
            result.ShouldBe(testData);
        }

        [Fact]
        public async Task ShouldDecryptComplexDataSuccessfully()
        {
            // Arrange
            var (publicKey, privateKey) = KeyFactory.GenerateKeyPair();
            var testData = new TestObject
            {
                Foo = "Foo",
                Bar = long.MaxValue,
                List = {"String1", "String2", "String3"}
            };
            var dataBlock = await Encryptor.Encrypt(publicKey, JsonConvert.SerializeObject(testData, _serializerSettings));
            
            // Act
            var result = await Decryptor.Decrypt<TestObject>(privateKey, dataBlock);
            
            // Assert
            testData.ToExpectedObject().ShouldEqual(result);
        }

        [Fact]
        public async Task ShouldThrowIfPrivateKeyIncorrect()
        {
            // Arrange
            var publicKey = KeyFactory.GenerateKeyPair().PublicKey;
            const string testData = "Test Data";
            var dataBlock = await Encryptor.Encrypt(publicKey, testData);
            
            // Act
            var differentPrivateKey = KeyFactory.GenerateKeyPair().PrivateKey;
            var exception = await Should.ThrowAsync<InvalidOperationException>(() => Decryptor.Decrypt<string>(differentPrivateKey, dataBlock));
            
            // Assert
            exception.Message.ShouldBe("There was a problem decrypting the data block. Potential data corruption or packet tampering has occurred.");
        }

        [Fact]
        public async Task ShouldThrowIfDataIsDifferent()
        {
            // Arrange
            var (publicKey, privateKey) = KeyFactory.GenerateKeyPair();
            const string testData = "Test Data";
            var dataBlock = await Encryptor.Encrypt(publicKey, testData);
            
            // Act
            var corruptedDataBlock = await Encryptor.Encrypt(publicKey, "Corruption Occurred");
            dataBlock.EncryptedData = corruptedDataBlock.EncryptedData;
            var exception = await Should.ThrowAsync<InvalidOperationException>(() => Decryptor.Decrypt<string>(privateKey, dataBlock));
            
            // Assert
            exception.Message.ShouldBe("The computed digital signature for the data block does not match the original digital signature.");
        }
    }
}