using System;
using Newtonsoft.Json;

namespace LightestNight.System.Encryption
{
    public class JsonPrimitiveConverter : JsonConverter
    {
        public override bool CanRead => false;

        public override bool CanConvert(Type objectType)
            => objectType != null && (objectType.IsPrimitive || objectType.IsAssignableFrom(typeof(Guid)));

        public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue,
            JsonSerializer serializer)
        {
            if (serializer == null)
                throw new ArgumentNullException(nameof(serializer));

            return serializer.Deserialize(reader, objectType);
        }

        public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
        {
            if (serializer == null)
                throw new ArgumentNullException(nameof(serializer));
            if (writer == null)
                throw new ArgumentNullException(nameof(writer));
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            
            if (serializer.TypeNameHandling == TypeNameHandling.All)
            {
                writer.WriteStartObject();
                writer.WritePropertyName("$type", false);

                writer.WriteValue(serializer.TypeNameAssemblyFormatHandling == TypeNameAssemblyFormatHandling.Full
                    ? value.GetType().AssemblyQualifiedName
                    : value.GetType().FullName);

                writer.WritePropertyName("$value", false);
                writer.WriteValue(value);
                writer.WriteEndObject();
            }
            else
            {
                writer.WriteValue(value);
            }
        }
    }
}