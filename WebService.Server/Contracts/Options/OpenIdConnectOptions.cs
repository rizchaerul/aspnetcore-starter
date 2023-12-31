namespace WebService.Server.Contracts.Options;

public class OpenIdConnectOptions
{
    public const string OpenIdConnect = "OpenIdConnect";

    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
}
