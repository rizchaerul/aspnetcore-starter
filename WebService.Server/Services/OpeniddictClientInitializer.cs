using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using WebService.Database.Entities;
using WebService.Server.Contracts.Options;

namespace WebService.Server.Services;

public class OpeniddictClientInitializer : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public OpeniddictClientInitializer(IServiceProvider serviceProvider) =>
        _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();

        var clients = _serviceProvider
            .GetRequiredService<IOptions<OpenIddictOptions>>()
            .Value
            .Clients;

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        foreach (var client in clients)
        {
            var openiddictClient = await manager.FindByClientIdAsync(
                client.ClientId,
                cancellationToken
            );
            // await manager.DeleteAsync(openiddictClient, cancellationToken);
            // openiddictClient = null;

            if (openiddictClient == null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = client.ClientId,
                    ClientSecret = client.ClientSecret,
                    DisplayName = client.ClientId,
                };

                foreach (var redirectUri in client.RedirectUris)
                {
                    descriptor.RedirectUris.Add(new Uri(redirectUri));
                }

                if (client.PostLogoutRedirectUris != null)
                {
                    foreach (var postLogoutRedirectUri in client.PostLogoutRedirectUris)
                    {
                        descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutRedirectUri));
                    }
                }

                foreach (var permissions in client.Permissions)
                {
                    // OpenIddictConstants.Permissions.Endpoints
                    // OpenIddictConstants.Permissions.GrantTypes
                    // OpenIddictConstants.Permissions.Scopes
                    // OpenIddictConstants.Permissions.ResponseTypes
                    // OpenIddictConstants.Permissions.Prefixes

                    descriptor.Permissions.Add(permissions);
                }

                await manager.CreateAsync(descriptor, cancellationToken);
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
