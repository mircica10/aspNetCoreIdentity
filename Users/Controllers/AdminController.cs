using Users.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace Users.Controllers
{
    [Authorize(Roles = "Admins")]
    public class AdminController : Controller {

        private UserManager<AppUser> userManager;
        private IUserValidator<AppUser> userValidator;
        private IPasswordValidator<AppUser> passwordValidator;
        private IPasswordHasher<AppUser> passwordHasher;

        public AdminController( UserManager<AppUser> userManager,
                                IUserValidator<AppUser> userValidator,
                                IPasswordValidator<AppUser> passwordValidator,
                                IPasswordHasher<AppUser> passwordHasher ) {
            this.userManager = userManager;
            this.userValidator = userValidator;
            this.passwordValidator = passwordValidator;
            this.passwordHasher = passwordHasher;
        }

        public ViewResult Index() => View(userManager.Users);

        public ViewResult Create() => View();

        [HttpPost]
        public async Task<IActionResult> Create(CreateModel model) {

            if (ModelState.IsValid) {
                AppUser user = new AppUser {
                    UserName = model.Name,
                    Email = model.Email
                };

                IdentityResult result = await userManager.CreateAsync(user, model.Password);

                if(result.Succeeded) {
                    return RedirectToAction("Index");
                }
                else {
                    foreach(IdentityError error in result.Errors) {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Delete(string id) {
            AppUser user = await userManager.FindByIdAsync(id);

            if (user != null) {
                IdentityResult identityResult = await userManager.DeleteAsync(user);

                if (identityResult.Succeeded) {
                    return RedirectToAction("Index");
                } 
                else {
                    foreach(IdentityError error in identityResult.Errors) {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            else {
                ModelState.AddModelError("", "User not found");
            }
            return View("Index", userManager.Users);
        }

        public async Task<IActionResult> Edit(string id) {
            var validUser = await userManager.FindByIdAsync(id);
            if (validUser != null) {
                return View(validUser);
            } 
            else {
                return RedirectToAction("Index");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Edit(string id, string email, string password) {
            AppUser appUser = await userManager.FindByIdAsync(id);
            if (appUser == null) {
                ModelState.AddModelError("", "User not found");
                return View(appUser);
            }
            appUser.Email = email;
            IdentityResult validEmail = await userValidator.ValidateAsync(userManager, appUser);
            if (!validEmail.Succeeded) {
                AddErrorsFromResult(validEmail);
            }
            IdentityResult validPass = null;
            if (!string.IsNullOrEmpty(password)) {
                validPass = await passwordValidator.ValidateAsync(userManager, appUser, password);

                if (validPass.Succeeded) {
                    appUser.PasswordHash = passwordHasher.HashPassword(appUser, password);
                }
                else {
                    AddErrorsFromResult(validPass);
                }
            }
            if ((validEmail.Succeeded && validPass == null) ||
                    (validEmail.Succeeded && password != string.Empty && validPass.Succeeded))  {
                IdentityResult result = await userManager.UpdateAsync(appUser);
                if (result.Succeeded) {
                    return RedirectToAction("Index");
                }
                else {
                    AddErrorsFromResult(result);
                }
            }
            return View(appUser);
        }


        private void AddErrorsFromResult(IdentityResult result) {
            foreach (var error in result.Errors) {
                ModelState.AddModelError("", error.Description);
            }
        }

    }
}
