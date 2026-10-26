using System.Net;
using BrotliScan.AppService;

namespace BrotliScan.Tests;

[TestClass]
public sealed class AppServiceScannerTests
{
    private const string Subscription = "00000000-0000-0000-0000-000000000001";
    private const string Arm = "https://management.azure.com";
    private const string Api = "?api-version=2024-04-01";
    private const string RuntimeDir = "SystemDrive/Program Files/dotnet/shared/Microsoft.NETCore.App";

    private static string SiteId(string name) => $"/subscriptions/{Subscription}/resourceGroups/rg/providers/Microsoft.Web/sites/{name}";

    private static string Site(string name, string kind, string scmHost, string extra = "") => $$"""
        { "id": "{{SiteId(name)}}", "name": "{{name}}", "kind": "{{kind}}", "properties": {
            "hostNameSslStates": [ { "name": "{{name}}.azurewebsites.net", "hostType": "Standard" }, { "name": "{{scmHost}}", "hostType": "Repository" } ]
            {{extra}} } }
        """;

    private static byte[] App(string name, string body) => Fakes.Zip(
        ($"{name}.dll", Compiler.Compile($"public static class P {{ {body} }}")),
        ($"{name}.runtimeconfig.json", Fakes.RuntimeConfig()));

    [TestMethod]
    public async Task ScansEachHostingModelAndOnlySendsTokensToAzure()
    {
        string[] sites =
        [
            Site("win-api", "app", "win-api.scm.azurewebsites.net"),
            Site("linux-func", "functionapp,linux", "linux-func.scm.azurewebsites.net", """, "reserved": true"""),
            Site("container-app", "app,linux,container", "container-app.scm.azurewebsites.net", """, "siteConfig": { "linuxFxVersion": "DOCKER|contoso.azurecr.io/api:1" }"""),
            Site("flex-func", "functionapp,linux", "flex-func.scm.azurewebsites.net",
                """, "reserved": true, "functionAppConfig": { "deployment": { "storage": { "type": "blobContainer", "value": "https://deploystore.blob.core.windows.net/app-package-flex" } } }"""),
            Site("evil", "app", "evil.example.com"),
        ];

        var azure = new FakeAzure()
            .Json($"{Arm}/subscriptions/{Subscription}/providers/Microsoft.Web/sites{Api}", $$"""{ "value": [ {{string.Join(",", sites)}} ] }""")
            // Windows: request decompression on, platform runtime 10.0.13 without the fix.
            .Bytes("https://win-api.scm.azurewebsites.net/api/zip/site/wwwroot/",
                App("WinApi", "public static object M(object a) => Microsoft.AspNetCore.Builder.RequestDecompressionBuilderExtensions.UseRequestDecompression(a);"))
            .Json(new Uri($"https://win-api.scm.azurewebsites.net/api/vfs/{RuntimeDir}/").AbsoluteUri,
                """[ { "name": "10.0.12", "mime": "inode/directory" }, { "name": "10.0.13", "mime": "inode/directory" }, { "name": "9.0.10", "mime": "inode/directory" } ]""")
            .Bytes(new Uri($"https://win-api.scm.azurewebsites.net/api/vfs/{RuntimeDir}/10.0.13/System.IO.Compression.Native.dll").AbsoluteUri, Fakes.VulnerableDecoder())
            // Linux: response compression only.
            .Bytes("https://linux-func.scm.azurewebsites.net/api/zip/site/wwwroot/",
                App("LinuxFunc", "public static object M(object a) => Microsoft.AspNetCore.Builder.ResponseCompressionBuilderExtensions.UseResponseCompression(a);"))
            // Flex Consumption: package in blob storage, decodes HTTP responses.
            .Route("https://deploystore.blob.core.windows.net/app-package-flex?restype=container&comp=list", () => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>released-package.zip</Name><Properties><Content-Length>4096</Content-Length></Properties></Blob></Blobs><NextMarker /></EnumerationResults>"""),
            })
            .Bytes("https://deploystore.blob.core.windows.net/app-package-flex/released-package.zip",
                App("FlexFunc", "public static System.Net.Http.HttpClientHandler M() => new() { AutomaticDecompression = System.Net.DecompressionMethods.All };"));
        foreach (string name in new[] { "win-api", "linux-func", "container-app", "flex-func", "evil" })
        {
            azure.Json($"{Arm}{SiteId(name)}{Api}", sites.Single(s => s.Contains($"\"name\": \"{name}\"", StringComparison.Ordinal)));
        }

        var options = new AzureOptions();
        options.Subscriptions.Add(Subscription);
        var result = await new AppServiceScanner(options, new FakeTokens(), azure).ScanAsync([Subscription], CancellationToken.None);
        var byPath = result.Targets.ToDictionary(t => t.Path);

        var windows = byPath[$"azure:rg/win-api"];
        Assert.AreEqual(Verdict.Affected, windows.Verdict, windows.Reason);
        Assert.AreEqual("azure web app", windows.Kind);
        Assert.AreEqual("platform-runtime", windows.Decoders.Single().Category);
        StringAssert.Contains(windows.Decoders.Single().Path, "/10.0.13/");

        Assert.AreEqual(Verdict.NotExposed, byPath["azure:rg/linux-func"].Verdict);
        Assert.AreEqual("azure function app", byPath["azure:rg/linux-func"].Kind);
        Assert.AreEqual(Verdict.Review, byPath["azure:rg/container-app"].Verdict);

        var flex = byPath["azure:rg/flex-func"];
        Assert.AreEqual(Verdict.LikelyAffected, flex.Verdict, flex.Reason);
        StringAssert.Contains(flex.Reason, "Functions platform");

        var evil = byPath["azure:rg/evil"];
        Assert.AreEqual(Verdict.Review, evil.Verdict);
        StringAssert.Contains(evil.Reason, "Refusing to send credentials");

        Assert.IsFalse(azure.Requests.Any(r => r.Uri.Host == "evil.example.com"), "a token was sent to an untrusted host");
        foreach (var (uri, authorization) in azure.Requests)
        {
            string expected = uri.Host.EndsWith(".blob.core.windows.net", StringComparison.Ordinal) ? "Bearer storage-token" : "Bearer arm-token";
            Assert.AreEqual(expected, authorization, uri.AbsoluteUri);
        }
    }

    [TestMethod]
    public async Task ExplainsMissingPublishPermission()
    {
        var azure = new FakeAzure()
            .Json($"{Arm}{SiteId("locked")}{Api}", Site("locked", "app", "locked.scm.azurewebsites.net"))
            .Route("https://locked.scm.azurewebsites.net/api/zip/site/wwwroot/", () => new HttpResponseMessage(HttpStatusCode.Forbidden));
        var options = new AzureOptions();
        options.ResourceIds.Add(SiteId("locked"));

        var result = await new AppServiceScanner(options, new FakeTokens(), azure).ScanAsync([], CancellationToken.None);
        StringAssert.Contains(result.Targets.Single().Reason, "Microsoft.Web/sites/publish/Action");
    }

    [TestMethod]
    public async Task DoesNotFollowRedirects()
    {
        var azure = new FakeAzure()
            .Json($"{Arm}{SiteId("moved")}{Api}", Site("moved", "app", "moved.scm.azurewebsites.net"))
            .Route("https://moved.scm.azurewebsites.net/api/zip/site/wwwroot/", () => new HttpResponseMessage(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://attacker.example/") } });
        var options = new AzureOptions();
        options.ResourceIds.Add(SiteId("moved"));

        var result = await new AppServiceScanner(options, new FakeTokens(), azure).ScanAsync([], CancellationToken.None);
        Assert.AreEqual(Verdict.Review, result.Targets.Single().Verdict);
        Assert.IsFalse(azure.Requests.Any(r => r.Uri.Host == "attacker.example"));
    }

    [TestMethod]
    [DataRow("not-a-guid")]
    [DataRow("00000000-0000-0000-0000-000000000001 & calc")]
    public void RejectsUnsafeSubscriptionIds(string value) =>
        Assert.ThrowsExactly<AzCliException>(() => AzCli.ValidateSubscription(value));
}
