namespace WebService.Server.Contracts.Options;

public class OpenIddictOptions
{
    public const string OpenIddict = "OpenIddict";

    public List<OpenIddictClient> Clients { get; set; } = new();
}

public class OpenIddictClient
{
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
}
