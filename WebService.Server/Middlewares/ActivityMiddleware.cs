using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using WebService.Database.Entities;

namespace WebService.Server.Middlewares;

public class ActivityMiddleware
{
    private readonly RequestDelegate _next;

    public ActivityMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ApplicationDbContext db)
    {
        // check for the attribute and skip everything else if it exists
        var endpoint = context.Features.Get<IEndpointFeature>()?.Endpoint;
        var attribute = endpoint?.Metadata.GetMetadata<TrackActivity>();

        if (attribute != null)
        {
            var accountId = context.User.GetClaim(OpenIddictConstants.Claims.Subject);
            var account = await db.Accounts
                .AsTracking()
                .FirstOrDefaultAsync(x => x.Id == Guid.Parse(accountId ?? Guid.Empty.ToString()));

            if (account != null)
            {
                account.LastActivityAt = attribute.IsUtc ? DateTime.UtcNow : DateTime.Now;
                await db.SaveChangesAsync();
            }
        }

        // Call the next delegate/middleware in the pipeline.
        await _next(context);
    }
}

public static class ActivityMiddlewareExtensions
{
    public static IApplicationBuilder UseActivityMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ActivityMiddleware>();
    }
}

public class TrackActivity : Attribute
{
    public bool IsUtc { get; set; } = true;
}
