using System.Text.Json;

namespace Common;


public interface IOutMessage
{
    OutMessageType Type { get; }
}

public class LogMessage : IOutMessage
{
    public OutMessageType Type { get; set; } = OutMessageType.Log;
    public string? Message { get; set; }
}

public class ErrorMessage : IOutMessage
{
    public OutMessageType Type { get; set; } = OutMessageType.Error;
    public string? Message { get; set; }
}

public class ReadyMessage : IOutMessage
{
    public OutMessageType Type { get; set; } = OutMessageType.Ready;
}

public enum OutMessageType
{
    Log,
    Ready,
    Payload,
    Error,
}

public class GeneralMessage : IOutMessage
{
    public OutMessageType Type { get; set; } = OutMessageType.Payload;
    public JsonDocument? Payload { get; set; }
}

class OutMessageConverter : TaggedUnionConverter<IOutMessage, OutMessageType>
{
    protected override string TagName => "type";

    protected override IOutMessage? FromEnum(JsonDocument document, JsonSerializerOptions options, OutMessageType type)
    {
        return type switch
        {
            OutMessageType.Log => document.Deserialize<LogMessage>(options),
            OutMessageType.Ready => document.Deserialize<ReadyMessage>(options),
            OutMessageType.Payload => document.Deserialize<GeneralMessage>(options),
            OutMessageType.Error => document.Deserialize<ErrorMessage>(options),
            _ => throw new JsonException("Unknown type variant")
        };
    }
}