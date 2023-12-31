using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using WebService.Server.Contracts.Constants;
using WebService.Server.Middlewares;

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
    [TrackActivity(IsUtc = false)]
    public ActionResult<string> Get()
    {
        return Ok("OK!");
    }

    [HttpGet("anonymous")]
    [AllowAnonymous]
    public ActionResult<string> GetAnonymous(string a)
    {
        return Ok("OK!");
    }
}
