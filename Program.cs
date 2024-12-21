using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add SQLite database
builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseSqlite("Data Source=users.db"));

// Add Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

/*
    AddIdentity<IdentityUser, IdentityRole>()

    Adds the default identity system configuration for the specified User and Role types.
    And returns an IdentityBuilder for creating and configuring the identity system.

    This method registers the ASP.NET Core Identity system with the Dependency
    Injection (DI) container.

    IdentityUser represents the user entity (a predefined class) that ASP.NET Core Identity
    uses for managing user accounts. It includes properties like:
    
    - UserName
    - Email
    - PasswordHash
    - PhoneNumber
    - And more...

    IdentityRole represents a role entity, which is used to define user roles for role-based
    access control (RBAC).
    
    ---
    
    AddEntityFrameworkStores<ApplicationDbContext>
*/

// Add JWT authentication
var jwtKey = builder.Configuration["JWT:Key"];
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "simple-aspnet-auth",
            ValidAudience = "simple-aspnet-auth",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!))
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
