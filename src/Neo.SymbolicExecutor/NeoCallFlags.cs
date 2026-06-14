namespace Neo.SymbolicExecutor;

public static class NeoCallFlags
{
    public const int None = 0;
    public const int ReadStates = 1 << 0;
    public const int WriteStates = 1 << 1;
    public const int AllowCall = 1 << 2;
    public const int AllowNotify = 1 << 3;
    public const int States = ReadStates | WriteStates;
    public const int ReadOnly = ReadStates | AllowCall;
    public const int All = States | AllowCall | AllowNotify;
}
