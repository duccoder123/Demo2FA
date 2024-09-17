using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MailKit.Net.Smtp;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Demo2FAWithIdentity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {

        private async Task<IdentityUser>? GetUser(string email) => await userManager.FindByEmailAsync(email);
        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            await userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            }, password);
            await userManager.SetTwoFactorEnabledAsync(await GetUser(email), true);
            return Ok("Account Created");
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            if(!await userManager.CheckPasswordAsync(await GetUser(email), password))
                return Unauthorized();

            var token = await userManager.GenerateTwoFactorTokenAsync(await GetUser(email),
                TokenOptions.DefaultProvider);

            return Ok(SendEmail(await GetUser(email), token));
        }

        private object? SendEmail(IdentityUser? user, string code)
        {
            // Build the email message
            StringBuilder emailBodyBuilder = new StringBuilder();
            // Append HTML content
            emailBodyBuilder.AppendLine("<html>");
            emailBodyBuilder.AppendLine("<head>");
            emailBodyBuilder.AppendLine("<style>");
            emailBodyBuilder.AppendLine("body { font-family : Ariral, san-serif; color: #333; margin: 20px;}");
            emailBodyBuilder.AppendLine("h1 {color : #007bff;}");
            emailBodyBuilder.AppendLine("p {margin : 10px p;}");
            emailBodyBuilder.AppendLine(".code {font-size : 24px; font-weight:bold;color: #28a745");
            emailBodyBuilder.AppendLine("</style>");
            emailBodyBuilder.AppendLine("</head>");
            emailBodyBuilder.AppendLine("<body>");

            // Gretting
            emailBodyBuilder.AppendLine($"<p>Dear {user.Email}, </p>");

            //Main Content
            emailBodyBuilder.AppendLine("<p>Thank you for using our application!</p>");
            emailBodyBuilder.AppendLine("<p>To complete your login process, please use the following verification code:</p>");

            // Verification Code
            emailBodyBuilder.AppendLine($"<p class='code'>{code}</p>");

            // Instructions
            emailBodyBuilder.AppendLine("<p>This code is valid for a short period, so please use it promptly.</p>");
            emailBodyBuilder.AppendLine("<p>If you did not request this code, please ignore this email</p>");

            //Closing
            emailBodyBuilder.AppendLine("<p>Best regards, </p>");
            emailBodyBuilder.AppendLine("<p>The Security Team</p>");

            emailBodyBuilder.AppendLine("</body>");
            emailBodyBuilder.AppendLine("</html>");

            string message = emailBodyBuilder.ToString();

            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse("cornell.haley@ethereal.email"));
            email.To.Add(MailboxAddress.Parse("cornell.haley@ethereal.email"));
            email.Subject = "2FA Verification";
            email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message };
            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("cornell.haley@ethereal.email", "BQ1xw8rSS1ZNYnYzhr");
            smtp.Send(email);
            smtp.Disconnect(true);

            return "2FA verification code sent to your email, kindly check and verify";
        }
        [HttpPost("verify2FA/{email}/{code}")]
        public async Task<IActionResult> Verify2FA(string email, string code)
        {
            await userManager.VerifyTwoFactorTokenAsync
                (await GetUser(email), TokenOptions.DefaultEmailProvider, code);
            return Ok(new[] { "Login successfully", GenerateToken(await GetUser(email)) });
        }

        private string GenerateToken(IdentityUser? user) 
        {
            var token = new JwtSecurityToken(
                    issuer: null,
                    audience: null,
                    claims: [new Claim(JwtRegisteredClaimNames.Email, user.Email)],
                    expires: null,
                    signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes("Abcxyz123456789QWERTyuiopzxczxcxzc")),
                    SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
    }
}
