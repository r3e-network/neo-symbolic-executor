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

    [Fact]
    public void Parse_EmptyJsonObject_ProducesEmptyManifest()
    {
        // The parser is lenient on missing fields by design — DevPack contracts may omit
        // optional sections like permissions or trusts. An empty manifest must not crash.
        var manifest = ContractManifest.FromJson("{}");
        manifest.Name.Should().BeEmpty();
        manifest.SupportedStandards.Should().BeEmpty();
        manifest.Abi.Methods.Should().BeEmpty();
        manifest.Abi.Events.Should().BeEmpty();
        manifest.Permissions.Should().BeEmpty();
        manifest.TrustsWildcard.Should().BeFalse();
        manifest.HasWildcardPermission.Should().BeFalse();
    }

    [Fact]
    public void Parse_InvalidJson_ThrowsFormatException()
    {
        // An empty string should not be silently accepted as a valid manifest.
        var act = () => ContractManifest.FromJson("");
        act.Should().Throw<System.FormatException>().WithMessage("*not valid JSON*");
    }

    [Fact]
    public void Parse_ExplicitTrustList_DoesNotFlagWildcard()
    {
        const string json = """
        { "name": "T", "trusts": ["0x1111111111111111111111111111111111111111"] }
        """;
        var manifest = ContractManifest.FromJson(json);
        manifest.TrustsWildcard.Should().BeFalse();
        manifest.Trusts.Items.Should().HaveCount(1);
    }

    [Fact]
    public void Parse_PermissionWithSpecificMethodsArray_NotWildcard()
    {
        // Audit detector context: a permission like {"contract":"X","methods":["transfer"]} is
        // tighter than {"methods":"*"} and must NOT trigger HasWildcardPermission.
        const string json = """
        {
          "name": "T",
          "permissions": [
            {"contract": "0x1111111111111111111111111111111111111111",
             "methods": ["transfer", "balanceOf"]}
          ],
          "trusts": []
        }
        """;
        var manifest = ContractManifest.FromJson(json);
        manifest.HasWildcardPermission.Should().BeFalse();
        manifest.Permissions.Should().HaveCount(1);
        manifest.Permissions[0].Methods.IsWildcard.Should().BeFalse();
        manifest.Permissions[0].Methods.Items.Should().Contain(new[] { "transfer", "balanceOf" });
    }

    [Fact]
    public void Parse_SupportedStandards_SilentlyDropsNonStringEntries()
    {
        // Audit C# #28 lineage: a non-string entry (number, object, array) inside
        // supportedstandards must NOT crash the parser. The good entries should still be picked up.
        const string json = """
        {
          "name": "T",
          "supportedstandards": ["NEP-17", 42, {"oops":"object"}, "NEP-11"]
        }
        """;
        var manifest = ContractManifest.FromJson(json);
        manifest.SupportedStandards.Should().Equal("NEP-17", "NEP-11");
    }

    [Fact]
    public void Parse_MethodWithSafeMissing_DefaultsToFalse()
    {
        const string json = """
        {
          "name": "T",
          "abi": {
            "methods": [
              { "name": "doStuff", "parameters": [], "returntype": "Void", "offset": 10 }
            ]
          }
        }
        """;
        var manifest = ContractManifest.FromJson(json);
        manifest.Abi.Methods[0].Safe.Should().BeFalse();
    }

    [Fact]
    public void Parse_AbiMethodArray_RejectsNonObjectEntries()
    {
        // A bare string or number in the methods array would crash node[".."] access — the
        // parser must guard each item with `is JsonObject`. Verify by mixing valid+invalid.
        const string json = """
        {
          "name": "T",
          "abi": {
            "methods": [
              "junk",
              { "name": "ok", "parameters": [], "returntype": "Void", "offset": 0 }
            ]
          }
        }
        """;
        var manifest = ContractManifest.FromJson(json);
        manifest.Abi.Methods.Should().HaveCount(1);
        manifest.Abi.Methods[0].Name.Should().Be("ok");
    }
}
