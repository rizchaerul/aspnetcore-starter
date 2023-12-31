using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using NSwag;
using NSwag.AspNetCore;
using NSwag.Generation.Processors.Security;
using OpenIddict.Abstractions;
using WebService.Database.Entities;
using WebService.Server.Contracts.Constants;
using WebService.Server.Contracts.Options;
using WebService.Server.Services;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
var configuration = builder.Configuration;

var openIdConnectOptions = configuration
    .GetSection(OpenIdConnectOptions.OpenIdConnect)
    .Get<OpenIdConnectOptions>();

services.Configure<OpenIddictOptions>(configuration.GetSection(OpenIddictOptions.OpenIddict));

// Add services to the container.
services.AddControllers();
services.AddRazorPages();

services.AddCors(options =>
{
    options.AddPolicy(
        name: PolicyConstants.CorsPolicy,
        policy =>
        {
            policy.AllowAnyOrigin();
            policy.AllowAnyHeader();
            policy.AllowAnyMethod();
        }
    );
});

services.AddOpenApiDocument(options =>
{
    options.AddSecurity(
        "bearer",
        new OpenApiSecurityScheme
        {
            AuthorizationUrl = $"{openIdConnectOptions?.Authority}/connect/authorize",
            TokenUrl = $"{openIdConnectOptions?.Authority}/connect/token",
            Flow = OpenApiOAuth2Flow.AccessCode,
            Type = OpenApiSecuritySchemeType.OAuth2,
            Scopes = new Dictionary<string, string> { { $"api", "Access APIs" }, },

            // If you want to use id_token instead of access_token
            // ExtensionData = new Dictionary<string, object?> { { "x-tokenName", "id_token" } },
        }
    );

    options.OperationProcessors.Add(new AspNetCoreOperationSecurityScopeProcessor("bearer"));
});

services.AddDbContextPool<ApplicationDbContext>(options =>
{
    // Set the default tracking behavior to no tracking.
    options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
    options.UseSqlServer(configuration.GetConnectionString("Database"));
    options.UseOpenIddict();
});

services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(
        CookieAuthenticationDefaults.AuthenticationScheme,
        options =>
        {
            options.LoginPath = "/account/login";
        }
    );

services
    .AddAuthorizationBuilder()
    .AddPolicy(
        PolicyConstants.ApiScopePolicy,
        policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim(OpenIddictConstants.Claims.Private.Scope, "api");
        }
    );

services
    .AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Allowed flows
        // PKCE
        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
        options.AllowClientCredentialsFlow();
        options.AllowRefreshTokenFlow();

        // Endpoints
        options
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetUserinfoEndpointUris("/connect/userinfo")
            .SetLogoutEndpointUris("/connect/endsession");

        // Encryption and signing of tokens
        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate()
            .DisableAccessTokenEncryption();

        // Supported claims
        options.RegisterClaims(OpenIddictConstants.Scopes.Email);
        options.RegisterClaims(OpenIddictConstants.Scopes.Profile);

        // Register scopes (permissions)
        options.RegisterScopes("api");
        options.RegisterScopes(OpenIddictConstants.Scopes.Email);
        options.RegisterScopes(OpenIddictConstants.Scopes.Profile);

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .DisableTransportSecurityRequirement()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableLogoutEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

services.AddHostedService<OpeniddictClientInitializer>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

if (app.Environment.IsDevelopment())
{
    app.UseOpenApi();
    app.UseSwaggerUi(options =>
    {
        options.OAuth2Client = new OAuth2ClientSettings
        {
            ClientId = openIdConnectOptions?.ClientId,
            UsePkceWithAuthorizationCodeGrant = true,
        };
    });

    // Generate Openiddict tables
    // app.Services.CreateScope().ServiceProvider.GetService<DbContext>()?.Database.EnsureCreated();
}

app.UseStaticFiles();
app.UseRouting();
app.UseCors(PolicyConstants.CorsPolicy);
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages();
app.Run();
