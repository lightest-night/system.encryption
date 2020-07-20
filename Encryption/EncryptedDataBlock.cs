namespace LightestNight.System.Encryption
{
    public class EncryptedDataBlock
    {
        /// <summary>
        /// The data in it's encrypted state
        /// </summary>
        public string EncryptedData { get; set; } = string.Empty;

        /// <summary>
        /// The signature used in encrypting the data
        /// </summary>
        public string DigitalSignature { get; set; } = string.Empty;

        /// <summary>
        /// The Initialisation Vector used in encrypting the data
        /// </summary>
        public string InitialisationVector { get; set; } = string.Empty;

        /// <summary>
        /// The Aes Key used in encrypting the data
        /// </summary>
        public string AesKey { get; set; } = string.Empty;

    }
}