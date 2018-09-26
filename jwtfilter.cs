using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IdentityModel.Tokens.Jwt;
using System.Web.Http.Filters;
using System.Web.Http.Controllers;
using Rantai.WeApi.AuthModule;
using System.Threading;
using System.Security.Principal;
using System.Net;
using System.Net.Http;

namespace Rantai.WeApi.Filter
{
    public class JWTAuthenticationFilter: AuthorizationFilterAttribute
    {
        public string Role { get; set; }
        protected virtual CustomPrincipal CurrentUser
        {
            get { return HttpContext.Current.User as CustomPrincipal; }
        }
        public override void OnAuthorization(HttpActionContext filterContext)
        {

            if (!IsUserAuthorized(filterContext))
            {
                ShowAuthenticationError(filterContext);
                return;
            }

            if (!string.IsNullOrWhiteSpace(Role))
            {
                if (!CurrentUser.IsInRole(Role))
                {
                    ShowAuthenticationError(filterContext);
                    return;
                }
            }
            base.OnAuthorization(filterContext);
        }

        private static void ShowAuthenticationError(HttpActionContext filterContext)
        {
            
            filterContext.Response = filterContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
        }
        public bool IsUserAuthorized(HttpActionContext actionContext)
        {
            var authHeader = FetchFromHeader(actionContext);


            if (authHeader != null)
            {
                var auth = new AuthenticationModule();
                JwtSecurityToken userPayloadToken = auth.GenerateUserClaimFromJWT(authHeader);

                if (userPayloadToken != null)
                {

                    var identity = auth.PopulateUserIdentity(userPayloadToken);
                    HttpContext.Current.User = identity;
                    //string[] roles = { "All" };
                    //var genericPrincipal = new ApplicationIdentity(identity, roles);
                    //Thread.CurrentPrincipal = genericPrincipal;
                    //var authenticationIdentity = Thread.CurrentPrincipal.Identity as JWTAuthenticationIdentity;
                    //if (authenticationIdentity != null && !String.IsNullOrEmpty(authenticationIdentity.UserName))
                    //{
                    //    authenticationIdentity.UserId = identity.UserId;
                    //    authenticationIdentity.UserName = identity.UserName;
                    //}
                    return true;
                }

            }
            return false;


        }
        private string FetchFromHeader(HttpActionContext actionContext)
        {
            string requestToken = null;

            var authRequest = actionContext.Request.Headers.Authorization;
            if (authRequest != null)
            {
                requestToken = authRequest.Parameter;
            }

            return requestToken;
        }

    }
}