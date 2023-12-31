using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebService.Database.Entities;

namespace WebService.Pages.Account
{
    public class LoginModel : PageModel
    {
        [BindProperty, Required]
        public string Email { get; set; } = string.Empty;

        [BindProperty, Required]
        public string Password { get; set; } = string.Empty;

        [BindProperty(SupportsGet = true)]
        public string? ReturnUrl { get; set; }

        private readonly ApplicationDbContext _db;

        public LoginModel(ApplicationDbContext db)
        {
            _db = db;
        }

        public ActionResult OnGet()
        {
            return Page();
        }

        public async Task<ActionResult> OnPost()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _db.Accounts.Where(x => x.Email == Email).FirstOrDefaultAsync();

            if (user == null)
            {
                ModelState.AddModelError("Email", "Email is not registered.");
                return Page();
            }

            var isPasswordCorrect = BCrypt.Net.BCrypt.Verify(Password, user.Password);

            if (!isPasswordCorrect)
            {
                ModelState.AddModelError("Password", "Password is not correct.");
                return Page();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString().ToUpper())
            };

            var claimsIdentity = new ClaimsIdentity(
                claims,
                CookieAuthenticationDefaults.AuthenticationScheme
            );
            await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

            if (string.IsNullOrEmpty(ReturnUrl) == false)
            {
                if (Url.IsLocalUrl(ReturnUrl))
                {
                    return Redirect(ReturnUrl);
                }
            }

            return Redirect("/");
        }
    }
}
