using System.Text.Json;
using System.Text.Json.Serialization;

namespace Common;

/// <summary>
/// Utility for working with rust style internally-tagged unions.
/// 
/// Requires specifying an enum, and an interface where each enum variant corresponds to
/// an implementor of the interface.
/// </summary>
public abstract class TaggedUnionConverter<TInterface, TEnum> : JsonConverter<TInterface>
    where TInterface : class
    where TEnum : struct, Enum
{
    protected abstract string TagName { get; }

    protected abstract TInterface? FromEnum(JsonDocument document, JsonSerializerOptions options, TEnum type);

    public override TInterface? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var doc = JsonDocument.ParseValue(ref reader);

        var prop = doc.RootElement.GetProperty(TagName).GetString();
        if (string.IsNullOrEmpty(prop))
        {
            throw new JsonException($"Missing tag \"{TagName}\"");
        }
        if (!Enum.TryParse<TEnum>(prop, true, out var type))
        {
            throw new JsonException($"Invalid tag \"{prop}\"");
        }
        return FromEnum(doc, options, type);
    }

    public override void Write(Utf8JsonWriter writer, TInterface value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, value.GetType(), options);
    }
}
