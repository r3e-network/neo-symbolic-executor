using System;
using System.IO;
using Neo.SymbolicExecutor;

namespace Neo.SymbolicExecutor.Cli;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintUsage();
            return 0;
        }

        try
        {
            return args[0] switch
            {
                "decode" => Decode(args[1..]),
                "explore" => Explore(args[1..]),
                "version" => Version(),
                _ => UnknownCommand(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 2;
        }
    }

    private static int Decode(string[] args)
    {
        if (args.Length < 1) { Console.Error.WriteLine("usage: neo-sym decode <script.bin>"); return 2; }
        var bytes = File.ReadAllBytes(args[0]);
        var program = ScriptDecoder.Decode(bytes);
        Console.WriteLine($"Decoded {program.Instructions.Length} instructions from {bytes.Length} bytes");
        foreach (var inst in program.Instructions)
        {
            string operand = inst.Operand.Length > 0
                ? $" {Convert.ToHexString(inst.Operand.Span)}"
                : "";
            string target = inst.Target >= 0 ? $" -> 0x{inst.Target:X4}" : "";
            Console.WriteLine($"  0x{inst.Offset:X4}  {inst.OpCode}{operand}{target}");
        }
        return 0;
    }

    private static int Explore(string[] args)
    {
        if (args.Length < 1) { Console.Error.WriteLine("usage: neo-sym explore <script.bin>"); return 2; }
        var bytes = File.ReadAllBytes(args[0]);
        var program = ScriptDecoder.Decode(bytes);
        var engine = new SymbolicEngine(program);
        var result = engine.Run();
        Console.WriteLine($"Explored {result.StatesExplored} states ({result.StepsExecuted} steps).");
        Console.WriteLine($"Final states: {result.FinalStates.Length}.");
        if (result.BudgetExceeded) Console.WriteLine($"Budget exceeded: {result.BudgetReason}");
        foreach (var s in result.FinalStates)
        {
            Console.WriteLine($"  {s.Status}: {s.TerminationReason ?? "<no reason>"}");
        }
        return result.AnyFaulted ? 1 : 0;
    }

    private static int Version()
    {
        Console.WriteLine($"neo-sym {typeof(SymbolicEngine).Assembly.GetName().Version}");
        return 0;
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"error: unknown command '{cmd}'");
        PrintUsage();
        return 2;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Neo Symbolic Executor CLI

            Usage:
              neo-sym decode  <script.bin>      Decode and disassemble a NeoVM script.
              neo-sym explore <script.bin>      Run symbolic exploration over a script.
              neo-sym version                   Print version.
            """);
    }
}
