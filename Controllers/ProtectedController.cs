using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace simple_net_auth.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ProtectedController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok( new { Message = "You have accessed a protected route!" });
    }
}