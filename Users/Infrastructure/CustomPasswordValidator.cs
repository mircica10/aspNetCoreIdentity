using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Users.Models;
using Microsoft.AspNetCore.Identity;


namespace Users.Infrastructure { 

    public class CustomPasswordValidator : PasswordValidator<AppUser> {

        public override async Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string password) {

            IdentityResult result = await base.ValidateAsync(manager, user, password);

            List<IdentityError> errors = result.Succeeded ? 
                new List<IdentityError>() : result.Errors.ToList();


            if (password.ToLower().Contains(user.UserName.ToLower())) {
                errors.Add(new IdentityError {
                    Code = "Password contains username",
                    Description = "Password cannot contain username"
                });
            }
            if (password.Contains("12345")) {
                errors.Add(new IdentityError {
                    Code = "Password contains sequence",
                    Description = "Password caoonot contains numeric sequence"
                });
            }

            return errors.Count == 0 ? 
                IdentityResult.Success : IdentityResult.Failed(errors.ToArray());

        }

    }
}
