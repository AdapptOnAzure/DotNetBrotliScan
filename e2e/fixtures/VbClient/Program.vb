Imports System.Net
Imports System.Net.Http

Module Program
    Sub Main(args As String())
        ' Decode gzip, deflate and brotli responses.
        Using handler As New HttpClientHandler With {.AutomaticDecompression = DecompressionMethods.GZip Or DecompressionMethods.Brotli}
            Using client As New HttpClient(handler)
                Console.WriteLine(client.GetStringAsync(args(0)).Result)
            End Using
        End Using
    End Sub
End Module
