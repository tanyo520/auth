using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace authFlow
{
    public class AuthHandle : IAuthenticationHandler, IAuthenticationSignInHandler, IAuthenticationSignOutHandler
    {
        AuthenticationScheme _authenticationScheme;
        HttpContext _context;

        public Task<AuthenticateResult> AuthenticateAsync()
        {
            var cookie = _context.Request.Cookies["myCookie"];
            if (string.IsNullOrEmpty(cookie))
            {
                AuthenticateResult authenticate= AuthenticateResult.NoResult();
                return Task.FromResult<AuthenticateResult>(authenticate);
            }
           byte[] bt = Convert.FromBase64String(cookie);
            AuthenticateResult authen =  AuthenticateResult.Success(TicketSerializer.Default.Deserialize(bt));
           // authen.Principal.AddIdentity(new ClaimsIdentity("Custom"));
            return Task.FromResult<AuthenticateResult>(authen);
        }

        public AuthenticationTicket Deserialize(string cookie) {
            
            return Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticationTicket>(cookie);
        }

        public string Serialize(AuthenticationTicket ticket)
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(ticket);
        }
        public Task ChallengeAsync(AuthenticationProperties properties)
        {
            _context.Response.Redirect("/login");
            return Task.CompletedTask;
        }

        public Task ForbidAsync(AuthenticationProperties properties)
        {
            _context.Response.StatusCode = 403;
            return Task.CompletedTask;
        }

        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            _authenticationScheme = scheme;
            _context = context;
            return Task.CompletedTask;
        }

        public Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
        {
            var ticket = new AuthenticationTicket(user, properties, _authenticationScheme.Name);
            byte[] ticketBytes= TicketSerializer.Default.Serialize(ticket);
            string base64Str = Convert.ToBase64String(ticketBytes);
            _context.Response.Cookies.Append("myCookie", base64Str);
            return Task.CompletedTask;
        }

        public Task SignOutAsync(AuthenticationProperties properties)
        {
            _context.Response.Cookies.Delete("myCookie");
            return Task.CompletedTask;
        }
    }
}
