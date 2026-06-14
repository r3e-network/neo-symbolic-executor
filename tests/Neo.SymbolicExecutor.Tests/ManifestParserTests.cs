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
    public void Parse_SupportedStandards_RejectsNonStringEntries()
    {
        const string json = """
        {
          "name": "T",
          "supportedstandards": ["NEP-17", 42, {"oops":"object"}, "NEP-11"]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*supportedstandards[1]*string*");
    }

    [Fact]
    public void Parse_TrustsRejectsNonStringEntries()
    {
        const string json = """
        {
          "name": "T",
          "trusts": ["0x1111111111111111111111111111111111111111", 42]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*trusts[1]*string*");
    }

    [Fact]
    public void Parse_TrustsRejectsInvalidShape()
    {
        const string json = """
        {
          "name": "T",
          "trusts": 42
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*trusts*array of strings*");
    }

    [Fact]
    public void Parse_ExplicitNullName_ThrowsFormatException()
    {
        const string json = """
        {
          "name": null
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*name*string*");
    }

    [Fact]
    public void Parse_MethodSafeRejectsNonBoolean()
    {
        const string json = """
        {
          "name": "T",
          "abi": {
            "methods": [
              { "name": "doStuff", "parameters": [], "returntype": "Void", "offset": 10, "safe": "false" }
            ]
          }
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*abi.methods[0].safe*boolean*");
    }

    [Fact]
    public void Parse_PermissionContractRejectsNonString()
    {
        const string json = """
        {
          "name": "T",
          "permissions": [
            { "contract": { "hash": "0x1111111111111111111111111111111111111111" }, "methods": [] }
          ]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*permissions[0].contract*string*");
    }

    [Fact]
    public void DeclaresStandard_NormalizesCommonNepTagVariants()
    {
        const string json = """
        {
          "name": "T",
          "supportedstandards": ["Nep17", "nep_11"]
        }
        """;
        var manifest = ContractManifest.FromJson(json);

        manifest.DeclaresStandard("NEP-17").Should().BeTrue();
        manifest.DeclaresStandard("NEP-11").Should().BeTrue();
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
    public void Parse_AbiMethodProofCriticalFields_MustBePresent()
    {
        var cases = new[]
        {
            (Field: "abi.methods[0].name", Json: """
            {
              "name": "T",
              "abi": {
                "methods": [
                  { "parameters": [], "returntype": "Void", "offset": 10 }
                ]
              }
            }
            """),
            (Field: "abi.methods[0].returntype", Json: """
            {
              "name": "T",
              "abi": {
                "methods": [
                  { "name": "doStuff", "parameters": [], "offset": 10 }
                ]
              }
            }
            """),
            (Field: "abi.methods[0].offset", Json: """
            {
              "name": "T",
              "abi": {
                "methods": [
                  { "name": "doStuff", "parameters": [], "returntype": "Void" }
                ]
              }
            }
            """),
            (Field: "abi.methods[0].parameters[0].type", Json: """
            {
              "name": "T",
              "abi": {
                "methods": [
                  {
                    "name": "doStuff",
                    "parameters": [
                      { "name": "account" }
                    ],
                    "returntype": "Void",
                    "offset": 10
                  }
                ]
              }
            }
            """),
        };

        foreach (var (field, json) in cases)
        {
            var act = () => ContractManifest.FromJson(json);
            act.Should().Throw<FormatException>()
                .WithMessage($"*{field}*");
        }
    }

    [Fact]
    public void Parse_AbiMethodArray_RejectsNonObjectEntries()
    {
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
        var act = () => ContractManifest.FromJson(json);
        act.Should().Throw<FormatException>().WithMessage("*abi.methods[0]*object*");
    }

    [Fact]
    public void Parse_PermissionMethodsRejectsNonStringArray()
    {
        const string json = """
        {
          "name": "T",
          "permissions": [
            { "contract": "*", "methods": 42 }
          ]
        }
        """;
        var act = () => ContractManifest.FromJson(json);
        act.Should().Throw<FormatException>().WithMessage("*permissions[0].methods*");
    }

    [Fact]
    public void Parse_NonEmptyFeatures_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "features": { "storage": true }
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*features*empty object*");
    }

    [Fact]
    public void Parse_ExplicitEmptyName_ThrowsFormatException()
    {
        const string json = """
        {
          "name": ""
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*name*non-empty*");
    }

    [Fact]
    public void Parse_DuplicateSupportedStandards_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "supportedstandards": ["NEP-17", "NEP-17"]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*supportedstandards*duplicate*");
    }

    [Fact]
    public void Parse_NormalizedDuplicateSupportedStandards_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "supportedstandards": ["NEP-17", "nep17"]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*supportedstandards*duplicate*");
    }

    [Fact]
    public void Parse_DuplicateAbiMethodSelectors_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "abi": {
            "methods": [
              {
                "name": "convert",
                "parameters": [{ "name": "value", "type": "Integer" }],
                "returntype": "Integer",
                "offset": 10,
                "safe": true
              },
              {
                "name": "convert",
                "parameters": [{ "name": "value", "type": "ByteString" }],
                "returntype": "Integer",
                "offset": 20,
                "safe": true
              }
            ]
          }
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>()
            .WithMessage("*abi.methods*duplicate method selector*convert/1*");
    }

    [Fact]
    public void Parse_AbiEventProofCriticalFields_MustBePresent()
    {
        var cases = new[]
        {
            (Field: "abi.events[0].name", Json: """
            {
              "name": "T",
              "abi": {
                "events": [
                  { "parameters": [] }
                ]
              }
            }
            """),
            (Field: "abi.events[0].name", Json: """
            {
              "name": "T",
              "abi": {
                "events": [
                  { "name": "", "parameters": [] }
                ]
              }
            }
            """),
            (Field: "abi.events[0].parameters[0].type", Json: """
            {
              "name": "T",
              "abi": {
                "events": [
                  {
                    "name": "Transfer",
                    "parameters": [
                      { "name": "from" }
                    ]
                  }
                ]
              }
            }
            """),
        };

        foreach (var (field, json) in cases)
        {
            var act = () => ContractManifest.FromJson(json);
            act.Should().Throw<FormatException>()
                .WithMessage($"*{field}*");
        }
    }

    [Fact]
    public void Parse_DuplicateAbiEventNames_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "abi": {
            "events": [
              {
                "name": "Transfer",
                "parameters": [
                  { "name": "from", "type": "Hash160" },
                  { "name": "to", "type": "Hash160" },
                  { "name": "amount", "type": "Integer" }
                ]
              },
              {
                "name": "Transfer",
                "parameters": [
                  { "name": "from", "type": "Hash160" },
                  { "name": "to", "type": "Hash160" },
                  { "name": "amount", "type": "Integer" },
                  { "name": "tokenId", "type": "ByteString" }
                ]
              }
            ]
          }
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>()
            .WithMessage("*abi.events*duplicate event name*Transfer*");
    }

    [Fact]
    public void Parse_DuplicateGroupPublicKeys_ThrowsFormatException()
    {
        string signature = Convert.ToBase64String(Enumerable.Repeat((byte)0x42, 64).ToArray());
        string json = $$"""
        {
          "name": "T",
          "groups": [
            {
              "pubkey": "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
              "signature": "{{signature}}"
            },
            {
              "pubkey": "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
              "signature": "{{signature}}"
            }
          ]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*groups[].pubkey*duplicate*");
    }

    [Fact]
    public void Parse_DuplicatePermissionContracts_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "permissions": [
            { "contract": "0x1111111111111111111111111111111111111111", "methods": ["transfer"] },
            { "contract": "0x1111111111111111111111111111111111111111", "methods": ["balanceOf"] }
          ]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*permissions[].contract*duplicate*");
    }

    [Fact]
    public void Parse_DuplicateTrusts_ThrowsFormatException()
    {
        const string json = """
        {
          "name": "T",
          "trusts": [
            "0x1111111111111111111111111111111111111111",
            "0x1111111111111111111111111111111111111111"
          ]
        }
        """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>().WithMessage("*trusts*duplicate*");
    }
}
