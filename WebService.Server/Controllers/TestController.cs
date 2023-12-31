using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using WebService.Server.Contracts.Constants;

namespace WebService.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(
    AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
    Policy = PolicyConstants.ApiScopePolicy
)]
public class TestController : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult> Get()
    {
        await Task.CompletedTask;
        return Ok();
    }
}
