using Common;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Server;

namespace TestServer;

public class TestServer : ReverseConnectServer
{
    TestNodeManager custom = null!;

    public TestNodeManager NodeManager => custom;

    protected override void OnServerStarting(ApplicationConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (Environment.GetEnvironmentVariable("OPCUA_NET_TEST_SERVER_TRACE") == "true")
        {
            Utils.SetTraceMask(Utils.TraceMasks.All);
            Utils.SetLogLevel(LogLevel.Trace);
            Utils.SetLogger(new CommsLogger());
        }

        base.OnServerStarting(configuration);
    }

    protected override void OnServerStarted(IServerInternal server)
    {
        ArgumentNullException.ThrowIfNull(server);

        base.OnServerStarted(server);

        // request notifications when the user identity is changed. all valid users are accepted by default.
        server.SessionManager.ImpersonateUser += new ImpersonateEventHandler(ImpersonateUser);
        // Auto accept untrusted, for testing
        CertificateValidator.AutoAcceptUntrustedCertificates = true;
    }

    protected override MasterNodeManager CreateMasterNodeManager(IServerInternal server, ApplicationConfiguration configuration)
    {
        custom = new TestNodeManager(server);
        return new MasterNodeManager(server, configuration, custom.NamespaceUris.First(), custom);
    }

    private void ImpersonateUser(Session _, ImpersonateEventArgs args)
    {
        if (args.NewIdentity is UserNameIdentityToken userNameToken)
        {
            if (userNameToken.UserName != "test" || userNameToken.DecryptedPassword != "pass")
            {
                throw ServiceResultException.Create(StatusCodes.BadIdentityTokenRejected,
                    "Incorrect username or password");
            }
        }
        else if (args.NewIdentity is AnonymousIdentityToken)
        {
            if (args.EndpointDescription.SecurityPolicyUri != SecurityPolicies.None)
            {
                throw ServiceResultException.Create(StatusCodes.BadIdentityTokenRejected,
                    "Anonymous token not permitted");
            }
        }
        else
        {
            throw ServiceResultException.Create(StatusCodes.BadIdentityTokenRejected,
                "Unsupported identity token");
        }

        args.Identity = new UserIdentity();
    }
}