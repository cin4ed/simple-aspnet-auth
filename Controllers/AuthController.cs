namespace simple_net_auth.Controllers;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var user = new IdentityUser { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok("User registered successfully");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);

        if (user == null || !(await _userManager.CheckPasswordAsync(user, model.Password)))
        {
            return Unauthorized("Invalid username or password");
        }

        var token = GenerateJwtToken(user);

        return Ok(new { token });
    }

    private string GenerateJwtToken(IdentityUser user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "simple-aspnet-auth",
            audience: "simple-aspnet-auth",
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: creds);
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public class RegisterModel
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}