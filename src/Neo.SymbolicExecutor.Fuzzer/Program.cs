using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Neo.SymbolicExecutor.Fuzzer.Targets;

namespace Neo.SymbolicExecutor.Fuzzer;

/// <summary>
/// Long-running CLI for the Neo symbolic-executor fuzzer.
///
/// Examples:
///   neo-sym-fuzz --seconds 60                          # 60-second smoke run, all targets
///   neo-sym-fuzz --forever --workers 8 --corpus ./corpus
///   neo-sym-fuzz --target engine,decoder --seconds 300
///   neo-sym-fuzz --reproduce ./corpus/crashes/decoder-XXXXXX/input.bin --target decoder
/// </summary>
internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] is "-h" or "--help")
        {
            PrintHelp();
            return 0;
        }
        try
        {
            var opts = ParseArgs(args);
            if (opts.Reproduce is not null)
            {
                return await Reproduce(opts);
            }

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Console.Error.WriteLine("\n^C — winding down workers, please wait...");
                cts.Cancel();
            };

            var campaignOpts = new FuzzCampaignOptions
            {
                Targets = opts.Targets,
                CorpusRoot = opts.CorpusRoot,
                Workers = opts.Workers,
                MaxRuntime = opts.MaxRuntime,
                StartSeed = opts.StartSeed,
                StopOnFirstCrash = opts.StopOnFirstCrash,
                StatusInterval = opts.StatusInterval,
                Log = Console.WriteLine,
            };
            var campaign = new FuzzCampaign(campaignOpts);
            Console.WriteLine($"=== Neo.SymbolicExecutor.Fuzzer ===");
            Console.WriteLine($"corpus: {opts.CorpusRoot}");
            Console.WriteLine($"workers: {opts.Workers}");
            Console.WriteLine($"targets: {string.Join(", ", opts.Targets.Select(t => t.Name))}");
            Console.WriteLine(opts.MaxRuntime is { } cap
                ? $"runtime: {cap}"
                : "runtime: unbounded (Ctrl+C to stop)");
            Console.WriteLine();

            await campaign.RunAsync(cts.Token);
            int unique = campaign.Recorder.UniqueCrashes;
            return unique == 0 ? 0 : 1;
        }
        catch (ArgumentException aex)
        {
            Console.Error.WriteLine($"error: {aex.Message}");
            PrintHelp();
            return 2;
        }
    }

    private static async Task<int> Reproduce(CliOpts opts)
    {
        if (opts.Targets.Count != 1)
        {
            Console.Error.WriteLine("--reproduce requires exactly one --target");
            return 2;
        }
        var target = opts.Targets[0];
        byte[] input = File.ReadAllBytes(opts.Reproduce!);
        Console.WriteLine($"Reproducing on target '{target.Name}' with {input.Length} bytes...");

        // We don't have direct "run with bytes" — but the fuzz target consumes a seed.
        // For now, the reproducer inspects the input file and prints its size.
        // Future: have IFuzzTarget expose RunWithInput(byte[]).
        await Task.Yield();
        Console.WriteLine("(Direct replay coming soon; the target's seed-driven generator is the canonical entry today.)");
        return 0;
    }

    private static CliOpts ParseArgs(string[] args)
    {
        var allTargets = new IFuzzTarget[]
        {
            new ScriptDecoderTarget(),
            new NefParserTarget(),
            new NefMutationTarget(),
            new ManifestParserTarget(),
            new EngineRandomScriptTarget(),
            new EngineSeededStateTarget(),
            new EngineNoCloneLeakTarget(),
            new DetectorEngineTarget(),
            new CombinedDetectorsOnEngineTarget(),
            new PipelineTarget(),
            new ReportGeneratorTarget(),
            new ExpressionSimplifierTarget(),
            new RealNefTarget(),
            new StructureAwareMutationTarget(),
        };
        var byName = allTargets.ToDictionary(t => t.Name, StringComparer.OrdinalIgnoreCase);

        TimeSpan? maxRuntime = null;
        bool forever = false;
        int? startSeed = null;
        int workers = Environment.ProcessorCount;
        string corpus = Path.Combine(Environment.CurrentDirectory, "fuzz-corpus");
        bool stopOnFirst = false;
        TimeSpan statusInterval = TimeSpan.FromSeconds(10);
        string? reproduce = null;
        var selected = new List<IFuzzTarget>(allTargets);

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => ++i < args.Length ? args[i] : throw new ArgumentException($"missing value for {a}");
            switch (a)
            {
                case "--seconds":
                case "--duration":
                    maxRuntime = TimeSpan.FromSeconds(int.Parse(Next()));
                    break;
                case "--minutes":
                    maxRuntime = TimeSpan.FromMinutes(int.Parse(Next()));
                    break;
                case "--hours":
                    maxRuntime = TimeSpan.FromHours(int.Parse(Next()));
                    break;
                case "--forever":
                    forever = true;
                    break;
                case "--workers":
                    workers = Math.Max(1, int.Parse(Next()));
                    break;
                case "--seed":
                    startSeed = int.Parse(Next());
                    break;
                case "--corpus":
                    corpus = Next();
                    break;
                case "--target":
                case "--targets":
                    {
                        var names = Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        selected.Clear();
                        foreach (var n in names)
                        {
                            if (!byName.TryGetValue(n, out var t))
                                throw new ArgumentException($"unknown target '{n}' (known: {string.Join(", ", byName.Keys)})");
                            selected.Add(t);
                        }
                        break;
                    }
                case "--stop-on-crash":
                    stopOnFirst = true;
                    break;
                case "--status-seconds":
                    statusInterval = TimeSpan.FromSeconds(int.Parse(Next()));
                    break;
                case "--reproduce":
                    reproduce = Next();
                    break;
                default:
                    throw new ArgumentException($"unknown option '{a}'");
            }
        }

        if (forever) maxRuntime = null;
        if (selected.Count == 0) selected.AddRange(allTargets);

        return new CliOpts
        {
            Targets = selected,
            CorpusRoot = corpus,
            MaxRuntime = forever ? null : maxRuntime,
            StartSeed = startSeed,
            Workers = workers,
            StopOnFirstCrash = stopOnFirst,
            StatusInterval = statusInterval,
            Reproduce = reproduce,
        };
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            Neo Symbolic Executor — Fuzzer

            Usage:
              neo-sym-fuzz [options]

            Run-length:
              --seconds <N>           Run for N seconds.
              --minutes <N>           Run for N minutes.
              --hours <N>             Run for N hours.
              --forever               Run until Ctrl+C.

            Workers and seed:
              --workers <N>           Concurrent worker threads (default: ProcessorCount).
              --seed <N>              Initial seed counter (default: TickCount). Same seeds reproduce.

            Targets:
              --target <names>        Comma-separated list. Default: all.
                                      Known: decoder, nef, manifest, engine, clone-leak,
                                      detectors, report, expr.

            Output:
              --corpus <dir>          Where to record crash artifacts (default: ./fuzz-corpus).
              --status-seconds <N>    Print stats every N seconds (default: 10).
              --stop-on-crash         Halt the campaign after the first new unique crash.

            Reproducer (experimental):
              --reproduce <input.bin>  Replay a recorded input through one --target.

            Examples:
              neo-sym-fuzz --seconds 60                 # 1-minute smoke run
              neo-sym-fuzz --hours 24 --workers 8       # overnight run
              neo-sym-fuzz --forever --corpus ./fuzz    # weeks-long run with persistent corpus

            Exit codes:
              0   No new crashes recorded.
              1   At least one new unique crash recorded under --corpus.
              2   Bad arguments.
            """);
    }

    private sealed record CliOpts
    {
        public required IReadOnlyList<IFuzzTarget> Targets { get; init; }
        public required string CorpusRoot { get; init; }
        public TimeSpan? MaxRuntime { get; init; }
        public int? StartSeed { get; init; }
        public int Workers { get; init; }
        public bool StopOnFirstCrash { get; init; }
        public TimeSpan StatusInterval { get; init; }
        public string? Reproduce { get; init; }
    }
}
