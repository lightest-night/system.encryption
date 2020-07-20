using Shouldly;
using Xunit;

namespace LightestNight.System.Encryption.Tests
{
    public class KeyFactoryTests
    {
        [Fact]
        public void ShouldCreateKeysWithoutFailure()
        {
            // Act
            var (publicKey, privateKey) = KeyFactory.GenerateKeyPair();
            
            // Assert
            publicKey.ShouldNotBeNull();
            publicKey.ShouldNotBeEmpty();
            
            privateKey.ShouldNotBeNull();
            privateKey.ShouldNotBeEmpty();
        }
    }
}