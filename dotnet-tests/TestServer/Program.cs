using Common;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;

namespace TestServer;

class CommsLogger : ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return null;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return true;
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var toLog = formatter(state, exception);
        Comms.LogToRust(toLog);
    }
}


internal sealed class Program
{
    private static async Task<int> Main(string[] args)
    {
        var configPath = args[0];
        var app = new ApplicationInstance
        {
            ConfigSectionName = "TestServer"
        };
        using var source = new CancellationTokenSource();
        TestServer server;
        ApplicationConfiguration cfg;
        try
        {
            cfg = await app.LoadApplicationConfiguration(configPath, true);
            await app.CheckApplicationInstanceCertificate(false, 0);
            server = new TestServer();
            await app.Start(server);
        }
        catch (ServiceResultException e)
        {
            Comms.Send(new ErrorMessage
            {
                Message = $"Fatal error: {e}. {e.InnerResult?.AdditionalInfo}"
            });
            return 1;
        }
        catch (Exception e)
        {
            Comms.Send(new ErrorMessage
            {
                Message = $"Fatal error: {e}"
            });
            return 1;
        }

        Comms.Send(new ReadyMessage());

        while (!source.Token.IsCancellationRequested)
        {
            await foreach (var message in Comms.ListenToInput(source.Token))
            {
                if (message is ShutdownMessage)
                {
                    source.Cancel();
                }
                else if (message is ChangeValueMessage ch)
                {
                    try
                    {
                        server.NodeManager.UpdateValue(ch);
                    }
                    catch (Exception ex)
                    {
                        Comms.Send(new ErrorMessage
                        {
                            Message = $"Fatal error setting value: {ex}"
                        });
                        return 1;
                    }
                }
                else if (message is ReverseConnectMessage rc)
                {
                    try
                    {
                        server.AddReverseConnection(new Uri(rc.Url ?? throw new ArgumentNullException("Url missing in ReverseConnectMessage")));
                    }
                    catch (Exception ex)
                    {
                        Comms.Send(new ErrorMessage
                        {
                            Message = $"Fatal error adding reverse connection: {ex}"
                        });
                        return 1;
                    }
                }
            }
        }


        return 0;
    }
}
