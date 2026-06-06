using System.Buffers.Text;
using Common;
using Opc.Ua;
using Opc.Ua.Server;

public class TestNodeManager : CustomNodeManager2
{
    private uint nextId;

    public TestNodeManager(IServerInternal server) : base(server, "opc.tcp://rust.test.localhost")
    {
        SystemContext.NodeIdFactory = this;
    }

    public override void CreateAddressSpace(IDictionary<NodeId, IList<IReference>> externalReferences)
    {
        lock (Lock)
        {
            PopulateCore(externalReferences);
        }

        base.CreateAddressSpace(externalReferences);
    }

    public void UpdateValue(ChangeValueMessage message)
    {
        var nodeId = NodeId.Parse(message.NodeId);
        var bytes = Convert.FromBase64String(message.Value!);

        var variant = new BinaryDecoder(bytes, Server.MessageContext).ReadVariant("");

        var vb = PredefinedNodes[nodeId];
        if (vb is not BaseDataVariableState state) throw new Exception("Not a variable");
        state.Value = variant.Value;
        state.Timestamp = DateTime.UtcNow;
        state.StatusCode = StatusCodes.Good;
        state.ClearChangeMasks(SystemContext, false);
    }

    private void PopulateCore(IDictionary<NodeId, IList<IReference>> externalReferences)
    {
        var root = CreateObject("CoreBase");
        AddExtRef(root, ObjectIds.ObjectsFolder, ReferenceTypeIds.Organizes, externalReferences);

        var varDouble = CreateVariable("VarDouble", DataTypeIds.Double);
        varDouble.Value = 0.0;
        AddNodeRelation(varDouble, root, ReferenceTypeIds.HasComponent);

        var varString = CreateVariable("VarString", DataTypeIds.String);
        varString.Value = "test 0";
        AddNodeRelation(varString, root, ReferenceTypeIds.HasComponent);

        var varEuInfo = CreateVariable("VarEuInfo", DataTypeIds.EUInformation,
            typeDefinitionId: VariableTypeIds.PropertyType);
        varEuInfo.Value = new EUInformation
        {
            NamespaceUri = "opc.tcp://test.localhost",
            DisplayName = "Degrees C",
            Description = "Temperature degrees Celsius",
        };
        AddNodeRelation(varEuInfo, root, ReferenceTypeIds.HasComponent);

        var mHello = new MethodState(null)
        {
            NodeId = new NodeId("EchoMethod", NamespaceIndex),
            BrowseName = new QualifiedName("EchoMethod", NamespaceIndex)
        };
        mHello.DisplayName = mHello.BrowseName.Name;
        mHello.InputArguments = new PropertyState<Argument[]>(mHello);
        mHello.InputArguments.NodeId = GenerateNodeId();
        mHello.OutputArguments = new PropertyState<Argument[]>(mHello);
        mHello.OutputArguments.NodeId = GenerateNodeId();
        mHello.InputArguments.Value = [
            new Argument("Thing", DataTypeIds.String, ValueRanks.Scalar, "Thing to echo"),
        ];
        mHello.OutputArguments.Value = [
            new Argument("Echo", DataTypeIds.String, ValueRanks.Scalar, "The echo"),
        ];
        mHello.OnCallMethod += (_, _, args, outArgs) =>
        {
            if (args.Count != 1)
            {
                return new ServiceResult(StatusCodes.BadInvalidArgument);
            }
            var m = args[0] as string;

            outArgs[0] = $"Echo: {m}";

            return ServiceResult.Good;
        };
        AddNodeRelation(mHello, root, ReferenceTypeIds.HasComponent);

        AddPredefinedNode(SystemContext, mHello);
    }

    public override NodeId New(ISystemContext context, NodeState node)
    {
        if (node is BaseInstanceState instance && instance.Parent != null)
        {
            return GenerateNodeId();
        }

        return node.NodeId;
    }

    private BaseObjectState CreateObject(string name, NodeId? nodeId = null)
    {
        var state = new BaseObjectState(null)
        {
            NodeId = nodeId ?? new NodeId(name, NamespaceIndex),
            BrowseName = new QualifiedName(name, NamespaceIndex)
        };
        state.DisplayName = state.BrowseName.Name;
        state.TypeDefinitionId = ObjectTypeIds.BaseObjectType;

        AddPredefinedNode(SystemContext, state);

        return state;
    }

    private BaseDataVariableState CreateVariable(string name, NodeId dataType,
        NodeId? nodeId = null, int dim = -1, NodeId? typeDefinitionId = null)
    {
        var state = new BaseDataVariableState(null)
        {
            NodeId = nodeId ?? new NodeId(name, NamespaceIndex),
            BrowseName = new QualifiedName(name, NamespaceIndex)
        };
        state.DisplayName = state.BrowseName.Name;
        state.TypeDefinitionId = typeDefinitionId ?? VariableTypeIds.BaseDataVariableType;
        state.DataType = dataType;
        state.ValueRank = ValueRanks.Scalar;
        if (dim > -1)
        {
            state.ValueRank = ValueRanks.OneDimension;
            state.ArrayDimensions = new[] { (uint)dim };
        }

        AddPredefinedNode(SystemContext, state);

        return state;
    }

    private void AddNodeRelation(NodeState state, NodeState parent, NodeId typeId)
    {
        state.AddReference(typeId, true, parent.NodeId);
        parent.AddReference(typeId, false, state.NodeId);
    }

    private void AddExtRef(NodeState state, NodeId id, NodeId typeId,
            IDictionary<NodeId, IList<IReference>> externalReferences)
    {
        if (!externalReferences.TryGetValue(id, out var references))
        {
            externalReferences[id] = references = new List<IReference>();
        }

        state.AddReference(typeId, true, id);
        references.Add(new NodeStateReference(typeId, false, state.NodeId));
    }

    private NodeId GenerateNodeId()
    {
        return new NodeId(Interlocked.Increment(ref nextId), NamespaceIndex);
    }
}