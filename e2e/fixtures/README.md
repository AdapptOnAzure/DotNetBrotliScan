# Scanner fixtures

Minimal projects, one per pattern the scanner must classify. They are compiled and
scanned by `e2e/run.sh`, never run or deployed, so they deliberately skip things a
real service needs (authentication, authorization, input limits).

| Project        | Pattern                                               | Expected verdict |
|----------------|-------------------------------------------------------|------------------|
| HelloApi       | POST endpoint + response compression (encoder only)   | not exposed      |
| InboundApi     | `UseRequestDecompression()` with default providers    | affected         |
| ManualBodyApi  | wraps `Request.Body` in `BrotliStream` by hand        | affected         |
| CustomProviderApi | removes `br`, then registers its own brotli provider | affected        |
| MitigatedApi   | request decompression with the `br` provider removed  | not exposed      |
| OutboundClient | `AutomaticDecompression = DecompressionMethods.All`   | affected         |
| SafeClient     | `AutomaticDecompression = GZip \| Deflate`            | not exposed      |
| DirectDecode   | `new BrotliStream(s, CompressionMode.Decompress)`     | affected         |
| CompressOnly   | `new BrotliStream(s, CompressionLevel.Optimal)`       | not exposed      |
| ConfigDriven   | `AutomaticDecompression` read from configuration      | review           |
| VbClient       | VB.NET, `AutomaticDecompression` includes Brotli      | affected         |
