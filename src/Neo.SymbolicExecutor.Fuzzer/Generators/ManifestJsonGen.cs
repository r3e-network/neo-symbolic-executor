using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Neo.SymbolicExecutor.Fuzzer.Generators;

/// <summary>
/// Generator for manifest-shaped JSON: mostly-valid documents with one or more fields
/// randomized to wrong types. Stresses the manifest parser without generating noise that's
/// just "JSON parser failed".
/// </summary>
public static class ManifestJsonGen
{
    private static readonly string[] Standards = { "NEP-17", "NEP-11", "NEP-26", "NEP-X" };
    private static readonly string[] ParameterTypes = { "Hash160", "Integer", "ByteString", "Boolean", "Any", "Array", "Map" };
    private static readonly string[] WildcardOrList = { "*", "[]", "[\"a\",\"b\"]" };

    public static string RandomManifest(Random rng)
    {
        var name = $"\"name\":\"{RandStr(rng, 4, 12)}\"";
        var groups = $"\"groups\":[]";
        var features = $"\"features\":{{}}";
        var standards = $"\"supportedstandards\":[\"{Standards[rng.Next(Standards.Length)]}\"]";

        // ABI methods — sometimes shape-correct, sometimes truncated, sometimes wrong-typed.
        int methodCount = rng.Next(0, 4);
        var methods = new List<string>(methodCount);
        for (int i = 0; i < methodCount; i++)
        {
            string mn = RandStr(rng, 3, 8);
            int paramCount = rng.Next(0, 4);
            var ps = Enumerable.Range(0, paramCount)
                .Select(_ => $"{{\"name\":\"{RandStr(rng, 1, 4)}\",\"type\":\"{ParameterTypes[rng.Next(ParameterTypes.Length)]}\"}}");
            string method = $"{{\"name\":\"{mn}\",\"parameters\":[{string.Join(",", ps)}],"
                          + $"\"returntype\":\"{ParameterTypes[rng.Next(ParameterTypes.Length)]}\","
                          + $"\"offset\":{rng.Next(0, 1024)},\"safe\":{(rng.Next(2) == 0 ? "true" : "false")}}}";
            methods.Add(method);
        }

        var abi = $"\"abi\":{{\"methods\":[{string.Join(",", methods)}],\"events\":[]}}";

        // 30% of the time, randomize one field to a wrong type to stress the parser.
        if (rng.NextDouble() < 0.30)
        {
            int which = rng.Next(5);
            switch (which)
            {
                case 0: name = $"\"name\":{rng.Next()}"; break;
                case 1: groups = "\"groups\":\"hello\""; break;
                case 2: features = "\"features\":[1,2,3]"; break;
                case 3: standards = "\"supportedstandards\":\"NEP-17\""; break;
                case 4: abi = "\"abi\":[]"; break;
            }
        }

        string permissions = rng.NextDouble() < 0.5
            ? $"\"permissions\":[{{\"contract\":\"{RandHash(rng)}\",\"methods\":\"{(rng.Next(2) == 0 ? "*" : RandStr(rng, 3, 6))}\"}}]"
            : $"\"permissions\":[{{\"contract\":\"*\",\"methods\":\"*\"}}]";
        string trusts = rng.Next(3) switch
        {
            0 => "\"trusts\":[]",
            1 => "\"trusts\":\"*\"",
            _ => $"\"trusts\":[\"{RandHash(rng)}\"]",
        };

        return $"{{{name},{groups},{features},{standards},{abi},{permissions},{trusts}}}";
    }

    private static string RandStr(Random rng, int min, int max)
    {
        const string ch = "abcdefghijklmnopqrstuvwxyz0123456789";
        int n = rng.Next(min, max + 1);
        var s = new char[n];
        for (int i = 0; i < n; i++) s[i] = ch[rng.Next(ch.Length)];
        return new string(s);
    }

    private static string RandHash(Random rng)
    {
        const string hex = "0123456789abcdef";
        var s = new char[42];
        s[0] = '0'; s[1] = 'x';
        for (int i = 2; i < 42; i++) s[i] = hex[rng.Next(16)];
        return new string(s);
    }
}
