namespace Neo.SymbolicExecutor;

internal static class NeoEcPoint
{
    public const int CompressedLength = 33;
    public const int UncompressedLength = 65;

    public static bool IsValidEncoding(byte[] bytes)
    {
        if (!HasSupportedEncodingShape(bytes))
            return false;

        try
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1");
            if (curve is null)
                return false;

            var point = curve.Curve.DecodePoint(bytes);
            return !point.IsInfinity;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException
            or System.ArithmeticException)
        {
            return false;
        }
    }

    private static bool HasSupportedEncodingShape(byte[] bytes) =>
        bytes is [0x02 or 0x03, ..] && bytes.Length == CompressedLength
        || bytes is [0x04, ..] && bytes.Length == UncompressedLength;
}
