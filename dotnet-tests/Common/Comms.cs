using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Common;

public static class Comms
{
    private static JsonSerializerOptions MakeOptions()
    {
        var res = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };
        res.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, false));
        res.Converters.Add(new OutMessageConverter());
        res.Converters.Add(new InMessageConverter());
        return res;
    }

    private static readonly JsonSerializerOptions options = MakeOptions();

    public static void Send(IOutMessage message)
    {
        using var stdout = Console.OpenStandardOutput();
        stdout.Write(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message, options)));
        stdout.WriteByte(0);
        stdout.Flush();
    }

    public static async IAsyncEnumerable<IInMessage> ListenToInput([EnumeratorCancellation] CancellationToken token)
    {
        using var stream = Console.OpenStandardInput();

        var batch = new List<byte>();
        var buffer = new byte[1024];
        while (!token.IsCancellationRequested)
        {
            var len = await stream.ReadAsync(buffer, token);
            foreach (var b in buffer.Take(len))
            {
                if (b == 0)
                {
                    var str = Encoding.UTF8.GetString([.. batch]);
                    var msg = JsonSerializer.Deserialize<IInMessage>(str, options) ?? throw new Exception("Got null message");
                    yield return msg;
                    batch.Clear();
                }
                else
                {
                    batch.Add(b);
                }
            }
        }
    }

    public static void LogToRust(string message)
    {
        Send(new LogMessage { Message = message });
    }
}
