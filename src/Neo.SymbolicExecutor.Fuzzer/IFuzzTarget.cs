using System;

namespace Neo.SymbolicExecutor.Fuzzer;

/// <summary>
/// A single fuzz target: a property checker over a randomly-generated input. Implementations
/// must be reentrant (the campaign runs many in parallel) and bounded in time/memory per call.
///
/// Failure protocol:
/// - Catch <see cref="ExpectedExceptions"/> and treat as success.
/// - Any other exception is a CRASH — the campaign will save the input + stack as an artifact.
/// - Returning false (without exception) signals an INVARIANT VIOLATION — saved with a
///   structured reason string.
/// </summary>
public interface IFuzzTarget
{
    string Name { get; }

    /// <summary>Exceptions that this target considers expected (parser-style failure modes).</summary>
    Type[] ExpectedExceptions { get; }

    /// <summary>
    /// Run a single iteration with the given seed. Return true on success; false on invariant
    /// violation. Throw to indicate a crash.
    /// </summary>
    /// <param name="seed">Per-iteration RNG seed for reproducibility.</param>
    /// <param name="reason">When returning false, set this to a short violation description.</param>
    /// <param name="reproInput">When returning false or throwing, set this to the bytes of the
    /// input that triggered the failure (used to write a reproducer artifact).</param>
    bool RunOnce(int seed, out string? reason, out byte[]? reproInput);
}
