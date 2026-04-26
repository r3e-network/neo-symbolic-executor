using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Tests;

public class ManifestParserTests
{
    private const string MinimalManifest = """
    {
      "name": "Sample",
      "groups": [],
      "features": {},
      "supportedstandards": ["NEP-17"],
      "abi": {
        "methods": [
          { "name": "transfer", "parameters": [
              {"name":"from","type":"Hash160"},
              {"name":"to","type":"Hash160"},
              {"name":"amount","type":"Integer"},
              {"name":"data","type":"Any"}
            ], "returntype": "Boolean", "offset": 100, "safe": false },
          { "name": "balanceOf", "parameters": [{"name":"account","type":"Hash160"}],
            "returntype": "Integer", "offset": 200, "safe": true }
        ],
        "events": [
          { "name": "Transfer", "parameters": [
              {"name":"from","type":"Hash160"},
              {"name":"to","type":"Hash160"},
              {"name":"amount","type":"Integer"}
            ] }
        ]
      },
      "permissions": [{"contract": "*", "methods": "*"}],
      "trusts": "*",
      "extra": null
    }
    """;

    [Fact]
    public void Parse_NEP17_Manifest_PopulatesAbi()
    {
        var manifest = ContractManifest.FromJson(MinimalManifest);
        manifest.Name.Should().Be("Sample");
        manifest.SupportedStandards.Should().Contain("NEP-17");
        manifest.Abi.Methods.Should().HaveCount(2);
        var transfer = manifest.FindMethod("transfer");
        transfer.Should().NotBeNull();
        transfer!.Parameters.Should().HaveCount(4);
        transfer.Safe.Should().BeFalse();
        manifest.FindMethod("balanceOf")!.Safe.Should().BeTrue();
        manifest.FindMethodAtOffset(200)!.Name.Should().Be("balanceOf");
    }

    [Fact]
    public void WildCardPermissions_AreFlagged()
    {
        var manifest = ContractManifest.FromJson(MinimalManifest);
        manifest.HasWildcardPermission.Should().BeTrue();
        manifest.TrustsWildcard.Should().BeTrue();
    }
}
