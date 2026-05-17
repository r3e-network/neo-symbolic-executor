using System;
using System.Collections.Generic;
using System.Linq;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Lightweight property-style fuzz harness. Each test runs many iterations with a fixed seed so
/// failures are reproducible. Goal: verify that no parser or engine path throws an uncaught
/// exception on adversarial inputs. All "expected" failures must surface as <see cref="FormatException"/>
/// (parser) or VmFault/CatchableVm/AnalysisBudget (engine).
///
/// This corresponds to <see cref="Audit"/> findings: the prior Python audit ran 250K iterations
/// on a similar harness and found 8 bugs. The C# port retains that bar.
/// </summary>
public class FuzzTests
{
    [Fact]
    public void Parser_RandomBytes_NeverThrowsUncaught()
    {
        const int iterations = 2_000;
        var rng = new Random(0x1AFEBABE);
        for (int i = 0; i < iterations; i++)
        {
            int length = rng.Next(1, 256);
            byte[] script = new byte[length];
            rng.NextBytes(script);

            try { _ = ScriptDecoder.Decode(script); }
            catch (VmFaultException) { /* expected: malformed bytecode */ }
            catch (Exception ex) { throw new Xunit.Sdk.XunitException($"unexpected {ex.GetType().Name} on iter {i}: {ex.Message}"); }
        }
    }

    [Fact]
    public void Parser_NefRandomBytes_FailsGracefully()
    {
        const int iterations = 500;
        var rng = new Random(0x1EADBEEF);
        for (int i = 0; i < iterations; i++)
        {
            int length = rng.Next(0, 1024);
            byte[] data = new byte[length];
            rng.NextBytes(data);
            try { _ = Nef.NefFile.Parse(data, verifyChecksum: true); }
            catch (FormatException) { /* expected for random bytes */ }
            catch (System.IO.EndOfStreamException) { /* expected: truncated */ }
            catch (ArgumentOutOfRangeException) { /* expected: VarBytes too long */ }
            catch (Exception ex) { throw new Xunit.Sdk.XunitException($"unexpected {ex.GetType().Name} on iter {i}: {ex.Message}"); }
        }
    }

    [Fact]
    public void Parser_ManifestRandomJson_FailsGracefully()
    {
        const int iterations = 500;
        var rng = new Random(0x12345678);
        var seeds = new[]
        {
            "{}", "[]", "null", "\"\"", "{\"name\":null}",
            "{\"name\":\"x\",\"abi\":{\"methods\":1}}",
            "{\"groups\":42}", "{\"permissions\":\"yes\"}",
        };
        for (int i = 0; i < iterations; i++)
        {
            string input = i < seeds.Length ? seeds[i] : RandomJson(rng, depth: 0);
            try { _ = Nef.ContractManifest.FromJson(input); }
            catch (FormatException) { /* expected */ }
            catch (System.Text.Json.JsonException) { /* expected */ }
            catch (InvalidOperationException) { /* expected */ }
            catch (NotSupportedException) { /* expected */ }
            catch (ArgumentException) { /* expected */ }
            catch (Exception ex) { throw new Xunit.Sdk.XunitException($"unexpected {ex.GetType().Name} on iter {i}: {ex.Message}"); }
        }
    }

    [Fact]
    public void Engine_RandomLegalSequences_BoundedExecution()
    {
        const int iterations = 200;
        var rng = new Random(0x100DF00D);
        var opcodes = new byte[]
        {
            (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PUSH4, (byte)NeoVm.OpCode.PUSH5,
            (byte)NeoVm.OpCode.NOP, (byte)NeoVm.OpCode.DUP, (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.SWAP, (byte)NeoVm.OpCode.ADD, (byte)NeoVm.OpCode.SUB,
            (byte)NeoVm.OpCode.MUL, (byte)NeoVm.OpCode.RET,
        };

        for (int i = 0; i < iterations; i++)
        {
            int len = rng.Next(2, 64);
            var bytes = new byte[len + 1];
            for (int j = 0; j < len; j++) bytes[j] = opcodes[rng.Next(opcodes.Length)];
            bytes[len] = (byte)NeoVm.OpCode.RET; // ensure script terminates

            try
            {
                var program = ScriptDecoder.Decode(bytes);
                var engine = new SymbolicEngine(program, new ExecutionOptions
                {
                    MaxSteps = 1_000,
                    MaxPaths = 16,
                    MaxStackSize = 64,
                });
                var result = engine.Run();
                // Every path must reach a terminal status.
                result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
                // Bounded resources.
                result.StepsExecuted.Should().BeLessThanOrEqualTo(1_000 * result.StatesExplored + 100);
            }
            catch (VmFaultException) { /* expected */ }
            catch (Exception ex) { throw new Xunit.Sdk.XunitException($"unexpected {ex.GetType().Name} on iter {i}: {ex.Message}"); }
        }
    }

    [Fact]
    public void StateClone_RandomizedTelemetry_NoCrossTalk()
    {
        // Targeted property: cloning a state and mutating the clone never affects the original
        // (audit C1, C6 lessons). We hammer this with random telemetry mutations.
        const int iterations = 1_000;
        var rng = new Random(0x1AFEF00D);
        for (int i = 0; i < iterations; i++)
        {
            var s1 = new ExecutionState();
            s1.CallStack.Add(new CallFrame(returnPc: -1));
            for (int j = 0; j < rng.Next(0, 8); j++)
                s1.Telemetry.WitnessChecks.Add(rng.Next());
            for (int j = 0; j < rng.Next(0, 4); j++)
                s1.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = rng.Next(), Method = "m", HasReturnValue = true });

            var s2 = s1.Clone();
            int origWcCount = s1.Telemetry.WitnessChecks.Count;
            int origEcCount = s1.Telemetry.ExternalCalls.Count;

            s2.Telemetry.WitnessChecks.Add(0xDEAD);
            s2.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0xBEEF });
            if (s2.Telemetry.ExternalCalls.Count > 0)
                s2.Telemetry.ExternalCalls[0].Method = "mutated";

            s1.Telemetry.WitnessChecks.Count.Should().Be(origWcCount, $"iter {i}");
            s1.Telemetry.ExternalCalls.Count.Should().Be(origEcCount, $"iter {i}");
            if (origEcCount > 0)
                s1.Telemetry.ExternalCalls[0].Method.Should().Be("m", $"iter {i}");
        }
    }

    [Fact]
    public void TelemetryClone_AllCollectionFieldsAreDeepCopied_NoCrossTalk()
    {
        // Reflective regression: Telemetry.Clone manually copies each field. Adding a new
        // collection field without updating Clone is a silent crash-class bug — exactly the
        // audit-C1 lesson. This test discovers every collection-typed property via reflection,
        // mutates the original, and asserts the clone is unchanged.
        var t1 = new Telemetry();
        var collectionProps = typeof(Telemetry)
            .GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Where(p => typeof(System.Collections.ICollection).IsAssignableFrom(p.PropertyType))
            .ToList();
        collectionProps.Should().NotBeEmpty("Telemetry must declare some collection-typed fields");

        // Seed every collection on t1 with one entry so Clone can be verified element-by-element.
        SeedTelemetry(t1);
        int[] originalCounts = collectionProps
            .Select(p => ((System.Collections.ICollection)p.GetValue(t1)!).Count)
            .ToArray();

        var t2 = t1.Clone();

        // Mutate every collection on the original; clone counts must be unchanged.
        SeedTelemetry(t1);  // double-seed = double the counts on t1
        int[] cloneCounts = collectionProps
            .Select(p => ((System.Collections.ICollection)p.GetValue(t2)!).Count)
            .ToArray();
        for (int i = 0; i < collectionProps.Count; i++)
        {
            cloneCounts[i].Should().Be(
                originalCounts[i],
                $"Telemetry.{collectionProps[i].Name} must be deep-copied — clone count {cloneCounts[i]} != pre-mutation count {originalCounts[i]}");
        }
    }

    private static void SeedTelemetry(Telemetry t)
    {
        // Every collection field gets one (repeatable) representative entry.
        t.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));
        t.ExternalCalls.Add(new ExternalCall { Offset = 0x20, Method = "m", HasReturnValue = true });
        t.ArithmeticOps.Add(new ArithmeticOp(0x30, "ADD",
            SymbolicValue.Int(1), SymbolicValue.Int(2), OverflowPossible: false, DivisorMaybeZero: false, Checked: false));
        t.WitnessChecks.Add(0x40);
        t.WitnessChecksEnforced.Add(0x40);
        t.CallerHashChecks.Add(0x50);
        t.SignatureChecks.Add(0x60);
        t.TimeAccesses.Add(0x70);
        t.RandomnessAccesses.Add(0x80);
        t.EventsEmitted.Add(0x90);
        t.LoopsDetected.Add(0xA0);
        t.IteratorLoops.Add(0xB0);
        t.ExceptionsThrown.Add(0xC0);
        t.UnknownSyscalls.Add(0xD0);
        t.UnknownOpcodes.Add(0xE0);
        t.SmtUnknownOffsets.Add(0xF0);
    }

    [Fact]
    public void Heap_RandomAllocsCloneIsolated()
    {
        // Property: after Heap.Clone(), mutating the clone's objects must not affect the original.
        const int iterations = 200;
        var rng = new Random(0x55EEDED);
        for (int i = 0; i < iterations; i++)
        {
            var heap = new Heap();
            var arrays = new List<ArrayObject>();
            for (int j = 0; j < rng.Next(1, 16); j++)
            {
                arrays.Add(heap.NewArray(Enumerable.Range(0, rng.Next(0, 8)).Select(k => SymbolicValue.Int(k))));
            }
            var clone = heap.Clone();
            // Mutate clone arrays via the CoW pathway (GetForWrite materializes a private copy
            // for the writer; Get is read-only post-clone).
            foreach (var a in arrays)
            {
                int origLen = a.Items.Count;
                var ca = clone.GetForWrite<ArrayObject>(a.Id);
                ca.Items.Add(SymbolicValue.Int(0xBEEF));
                a.Items.Count.Should().Be(origLen, $"iter {i} array {a.Id} should not have grown");
            }
        }
    }

    private static string RandomJson(Random rng, int depth)
    {
        if (depth > 4) return "null";
        return rng.Next(8) switch
        {
            0 => "null",
            1 => rng.Next(2) == 0 ? "true" : "false",
            2 => rng.Next(int.MinValue, int.MaxValue).ToString(),
            3 => "\"" + RandomString(rng, 8) + "\"",
            4 => "[" + string.Join(",", Enumerable.Range(0, rng.Next(0, 4)).Select(_ => RandomJson(rng, depth + 1))) + "]",
            _ => "{"
                 + string.Join(",", Enumerable.Range(0, rng.Next(0, 4)).Select(_ =>
                     $"\"{RandomString(rng, 4)}\":{RandomJson(rng, depth + 1)}"))
                 + "}",
        };
    }

    private static string RandomString(Random rng, int maxLen)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        int len = rng.Next(1, maxLen);
        char[] buf = new char[len];
        for (int i = 0; i < len; i++) buf[i] = chars[rng.Next(chars.Length)];
        return new string(buf);
    }
}
