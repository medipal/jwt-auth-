using Rantai.Common.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;

namespace Rantai.WeApi.AuthModule
{
    public class CustomPrincipal : ICustomPrincipal
    {
        public IIdentity Identity { get; private set; }
        public bool IsInRole(string role)
        {
            if (role == (Enum.GetName(typeof(Enums.LoginRole), Type)))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public CustomPrincipal(string token)
        {
            Identity = new GenericIdentity(token);
        }
        public int UserId { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int Type { get; set; }
        public string Permissions { get; set; }
    }
}
