using Microsoft.AspNetCore.Mvc;
using webAdmin.Data;
using webAdmin.ViewModels;
using System.Security.Cryptography;
using webAdmin.Extenstions;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using webAdmin.Services;
using System.Text;
using System.Data.Entity;
using System.Net;
using Microsoft.AspNetCore.Localization;

namespace webAdmin.Controllers
{
    public class UsersController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IMailService _mail;
        private readonly ILogger<UsersController> _logger;

        public UsersController(ApplicationDbContext context, ILogger<UsersController> logger, IMailService mail)
        {
            _context = context;
            _logger = logger;
            _mail = mail;
        }

        static string EncryptStringToBytes_Aes(string plainText, string keyString)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (keyString == null || keyString.Length <= 0)
                throw new ArgumentNullException("keyString");

            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.Key = Encoding.UTF8.GetBytes(keyString);
                aesAlg.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            String output = Convert.ToBase64String(encrypted);
            return output;
        }

        static string DecryptStringFromBytes_Aes(string cipherText, string keyString)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (keyString == null || keyString.Length <= 0)
                throw new ArgumentNullException("keyString");

            string output;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.Key = Encoding.UTF8.GetBytes(keyString);
                aesAlg.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                byte[] xBuff;
                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        byte[] xXml = Convert.FromBase64String(cipherText);
                        csDecrypt.Write(xXml, 0, xXml.Length);
                    }

                    xBuff = msDecrypt.ToArray();
                }
                output = Encoding.UTF8.GetString(xBuff);
                
            }

            return output;
        }
     
        public IActionResult Index()
        {
            return View();
        }

        // GET: Users/SignUp
        public IActionResult SignUp(string? returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (User.Identity == null)
            {
                return Problem("Entity set 'User.Identity'  is null.");
            }

            if (User.Identity.IsAuthenticated)
            {
                return LocalRedirect(returnUrl);
            }

            return View();
        }

        // GET: Users/SginIn
        public IActionResult SignIn(string? returnUrl)
        {
            ViewData["ReturnUrl"] = returnUrl;

            string? cookieValueFromReq = Request.Cookies["admin_auth_cookie"];

            returnUrl = returnUrl ?? Url.Content("~/");

            if (cookieValueFromReq != null)
            {
                ClaimsPrincipal user = User;

                if (User.Identity == null)
                {
                    return Problem("Entity set 'User.Identity'  is null.");
                }

                if (User.Identity.IsAuthenticated)
                    return LocalRedirect(returnUrl);
                
            }

            return View();
        }

        // GET: Users/ChangePassword
        public IActionResult ChangePassword()
        {
            return View();
        }

        // GET: Users/ResetPassword
        public IActionResult ResetPassword()
        {
            return View();
        }

        // POST: Users/ResetPassword
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword([Bind("email")] ResetPassword resetPasswordUser)
        {
            if (!ModelState.IsValid)
            {
                return View(resetPasswordUser);
            }

            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            User? user = _context.Users.Where(x => x.email == resetPasswordUser.email).FirstOrDefault();

            var key = "E546C8DF278CD5931069B522E695D4F2";
            DateTime currentTime = DateTime.Now;
            DateTime x30MinsLater = currentTime.AddMinutes(30);
            string dateString = x30MinsLater.ToString("yyyy-MM-dd HH:mm:ss");

#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
            string content = user.idx
                             + "i"
                             + Convert.ToString((int)currentTime.Subtract(new DateTime(1970, 1, 1)).TotalSeconds);
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.
            string encrypted;
            encrypted = EncryptStringToBytes_Aes(content, key);

            string authUrl = "https://qa-net-cst.four33.com:9050/Users/SendNewPassword?fingerprint=" + encrypted.Replace("+", "@") + "&id=" + user.user_id;

#pragma warning disable CS8604 // 가능한 null 참조 인수입니다.
            MailData mailData = new MailData(
                to: new List<string> { resetPasswordUser.email },
                subject: "[webAdmin] Request password reset",
                body: "Click the URL below to proceed with password reset. Click the URL and a new password will be emailed to you. <br/> The URL below is valid until "
                + dateString + " <br/><br/> Password reset url : " + authUrl
                );
#pragma warning restore CS8604 // 가능한 null 참조 인수입니다.

            bool result = await _mail.SendAsync(mailData, new CancellationToken());

            if (result)
            {
                //return StatusCode(StatusCodes.Status200OK, "Mail has successfully been sent.");
                TempData["success"] = "Mail has successfully been sent.";
            }
            else
            {
                //return StatusCode(StatusCodes.Status500InternalServerError, "An error occured. The Mail could not be sent.");
                TempData["error"] = "An error occured. The Mail could not be sent.";
            }

            return RedirectToAction(nameof(ResetPassword));
        }

        // Get: Users/SendNewPassword
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpGet]
        public async Task<IActionResult> SendNewPassword(string id, string fingerprint)
        {
            int currentTime = Convert.ToInt32(Convert.ToString((int)DateTime.Now.Subtract(new DateTime(1970, 1, 1)).TotalSeconds));
            
            var key = "E546C8DF278CD5931069B522E695D4F2";

            System.Diagnostics.Trace.WriteLine(fingerprint);

            fingerprint = System.Web.HttpUtility.UrlDecode(fingerprint).Replace("@", "+");

            System.Diagnostics.Trace.WriteLine(fingerprint);
            string decrypted;
            decrypted = DecryptStringFromBytes_Aes(fingerprint, key);

            System.Diagnostics.Trace.WriteLine(decrypted);

            string[] exploded = decrypted.Split('i');

            int idx = Convert.ToInt32(exploded[0]);
            int requestTime = Convert.ToInt32(exploded[1]);

            if (_context.Users == null || _context.Pw_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users or Pw_log'  is null.");
            }

            User? user = _context.Users.Where(x => x.user_id == id).FirstOrDefault();

#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
            if ((idx != user.idx) || (currentTime - requestTime) > 1800)
            {
                //return StatusCode(StatusCodes.Status500InternalServerError, "Auth time has expired.");
                TempData["error"] = "Auth time has expired";
                return RedirectToAction(nameof(ResetPassword));
            }
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.

            var generator = new PasswordGenerator()
            {
                Length = 8,
                MinLowercases = 1,
                MinUppercases = 1,
                MinDigits = 1,
                MinSpecials = 1
            };

            var password = generator.Generate();

            var HashPassword = PasswordHasher.HashPassword(password); ;

            user.user_pw = HashPassword;
            user.pw_error_count = 0;
            user.pw_update_date = DateTime.Now;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            PwLog pw_log = new PwLog();
            pw_log.user_idx = user.idx;
            pw_log.user_id = user.user_id;
            pw_log.user_pw = HashPassword;
            _context.Pw_log.Add(pw_log);

            string changePasswordUrl = "https://qa-net-cst.four33.com:9050/Users/ChangePassword";

#pragma warning disable CS8604 // 가능한 null 참조 인수입니다.
            MailData mailData = new(to: new List<string> { user.email },
                subject: "[webAdmin] Reset password Success",
                body: "Password has successfully Reset. <br/> New password : " + password + "<br/><br/>You can change the password to the desired password at the following URL : <a href='" + changePasswordUrl + "'>Change Password</a>");
#pragma warning restore CS8604 // 가능한 null 참조 인수입니다.

            bool result = await _mail.SendAsync(mailData, new CancellationToken());

            return StatusCode(StatusCodes.Status200OK, "Password has Reset. Mail has successfully been sent.");
        }

        // POST: Users/SignUp
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SignUp([Bind("idx,user_id,user_pw,user_pw_confirm,name,dept,email,status,pw_update_date,pw_error_count,users_group_idx")] User user)
        {
            if (!ModelState.IsValid)
            {
                return View(user);
            }

            if (user.user_pw == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            string password = user.user_pw;
            var result = PasswordHasher.HashPassword(password);

            user.user_pw = result;

            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            if (_context.Pw_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Pw_log'  is null.");
            }

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            PwLog pw_log = new PwLog();
            pw_log.user_idx = user.idx;
            pw_log.user_id = user.user_id;
            pw_log.user_pw = result;
            _context.Pw_log.Add(pw_log);
            await _context.SaveChangesAsync();

            TempData["success"] = "Success sign up";
            return RedirectToAction(nameof(SignIn));
        }

        public static int GetMonthDifference(DateTime startDate, DateTime endDate)
        {
            int monthsApart = 12 * (startDate.Year - endDate.Year) + startDate.Month - endDate.Month;
            return Math.Abs(monthsApart);
        }

        //[ValidateAntiForgeryToken]
        // POST: Users/SignIn
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        public async Task<IActionResult> SignIn([Bind("user_id,user_pw")] SignIn signUser)
        {
            if (!ModelState.IsValid)
            {
                return View(signUser);
            }

            if (_context.Users == null || _context.Login_log == null)
            {
                return Json(new { status = "error", message = "Something wrong." });
            }

            if(signUser.user_id == null || signUser.user_pw == null)
            {
                return Json(new { status = "error", message = "Something wrong." });
            }

            User? user = _context.Users.Where(x => x.user_id == signUser.user_id).FirstOrDefault();

#pragma warning disable CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.
            IPAddress remoteIpAddress = Request.HttpContext.Connection.RemoteIpAddress;
#pragma warning restore CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.

            string login_ip = "";
            if (remoteIpAddress != null)
            {
                // If we got an IPV6 address, then we need to ask the network for the IPV4 address 
                // This usually only happens when the browser is on the same machine as the server.
                if (remoteIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    remoteIpAddress = System.Net.Dns.GetHostEntry(remoteIpAddress).AddressList
                        .First(x => x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                }
                login_ip = remoteIpAddress.ToString();
            }

            if (user == null)
            {
                return Json(new { status = "error", message = $"Id {signUser.user_id} is not exist." });
            }

            LoginLog login_log = new LoginLog();
            login_log.user_id = user.user_id;
            login_log.user_idx = user.idx;
            login_log.login_ip = login_ip;
            login_log.success_yn = "Y";


            if (user.user_pw == null)
            {
                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();
                return Json(new { status = "error", message = $"Password {signUser.user_pw} is not exist." });
            }

            string password = user.user_pw;
            int passwordErrorCount = user.pw_error_count;

            var right = PasswordHasher.VerifyHashedPassword(signUser.user_pw, password);

            if (right == false)
            {
                System.Diagnostics.Trace.WriteLine(passwordErrorCount);
                
                if (passwordErrorCount < 100)
                {
                    user.pw_error_count = passwordErrorCount + 1;
                    _context.Users.Update(user);
                    _context.SaveChanges();
                }

                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                return Json(new { status = "error", message = "Please note that if you enter the password incorrectly " +
                    "<span style='font-weight:bold;color:red;'>5 times</span>, " +
                    "you will have to reset the password. " +
                    "<br/><br/> If you have forgotten your password, please reset it."
                });
            }

            if (user.pw_error_count > 5)
            {
                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                return Json(new { status = "error", message = "Your account has been " +
                    "<span style='font-weight:bold;color:red;'>blocked</span> because you have entered too many passwords." +
                    "<br/> Please reset your password." });
            }

#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
#pragma warning disable CS8604 // 가능한 null 참조 인수입니다.
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.email),
                new Claim(ClaimTypes.Name, user.user_id),
                new Claim(ClaimTypes.Role, "Administrator")
            };
#pragma warning restore CS8604 // 가능한 null 참조 인수입니다.
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                //AllowRefresh = <bool>,
                // Refreshing the authentication session should be allowed.
                AllowRefresh = true,

                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30),
                // The time at which the authentication ticket expires. A 
                // value set here overrides the ExpireTimeSpan option of 
                // CookieAuthenticationOptions set with AddCookie.

                IsPersistent = true,
                // Whether the authentication session is persisted across 
                // multiple requests. When used with cookies, controls
                // whether the cookie's lifetime is absolute (matching the
                // lifetime of the authentication ticket) or session-based.

                //IssuedUtc = <DateTimeOffset>,
                // The time at which the authentication ticket was issued.

                //RedirectUri = <string>
                // The full path or absolute URI to be used as an http 
                // redirect response value.
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            _logger.LogInformation("User {Id} logged in at {Time}.",
                user.user_id, DateTime.UtcNow);

            string returnUrl = HttpContext.Request.Query["returnUrl"].ToString();
            returnUrl = returnUrl ?? Url.Content("~/");

            if (passwordErrorCount > 0)
            {
                user.pw_error_count = 0;
                _context.Users.Update(user);
                _context.SaveChanges();
            }

            if (_context.Login_log == null)
            {
                //login_log.success_yn = "N";
                //_context.Login_log.Add(login_log);
                //await _context.SaveChangesAsync();
                return Json(new { status = "error", message = "Something wrong." });
            }

            var recentLoginLog = _context.Login_log.Where(x => x.user_idx == user.idx && x.success_yn == "Y").OrderByDescending(x => x.log_date).Take(1).SingleOrDefault();
            
            DateTime now = DateTime.UtcNow;
            DateTime preSixMonthDate = now.AddMonths(-6);
            DateTime preThreeMonthDate = now.AddMonths(-3);

            if (recentLoginLog != null)
            {
                DateTime recentLoginLogDate = recentLoginLog.log_date;

                if (recentLoginLogDate < preSixMonthDate)
                {
                    user.status = 21;
                    user.block_date = preSixMonthDate;
                    user.block_reason = "long-term unconnected";
                    _context.Users.Update(user);
                    _context.SaveChanges();
                }
            }

            _logger.LogInformation("preThreeMonthDate : {Time}.", preThreeMonthDate);

            DateTime pwUpdateDate = user.pw_update_date;

            if (pwUpdateDate < preThreeMonthDate)
            {
                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                return Json(new
                {
                    status = "error",
                    message = "More than <span style='font-weight:bold;color:red;'>3</span> months have passed since the password change date." +
                    "<br/>Please change your password."
                });
            }

            if (user.status == 0)
            {
                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                await HttpContext.SignOutAsync();
                return Json(new { 
                    status = "unauthenticated", 
                    message = "You are an unauthenticated user. <br/>" +
                    "Please apply for authentication to the administrator."
                });
            } else if (user.status == 20)
            {
                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                await HttpContext.SignOutAsync();
                return Json(new
                {
                    status = "withdrawn",
                    message = "You are a user who has withdrawn from membership. <br/>" +
                    "Please apply for authentication to the administrator."
                });
            } else if (user.status == 21)
            {
                login_log.success_yn = "N";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                await HttpContext.SignOutAsync();
                return Json(new
                {
                    status = "blocked",
                    message = "You are a blocked user. <br/>" +
                    "Please apply for authentication to the administrator."
                });
            }

            _context.Login_log.Add(login_log);
            await _context.SaveChangesAsync();

            return Json(new { status = "success", message = "Sucess sign in.", returnUrl = returnUrl });
            //return LocalRedirect(returnUrl);
        }

        // POST: Users/ChangePassword
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword([Bind("user_id,user_pw,new_user_pw,new_user_pw_confirm")] ChangePassword changePasswordUser)
        {
            if (!ModelState.IsValid)
            {
                TempData["error"] = "error!";
                return View(changePasswordUser);
            }

            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            if (_context.Pw_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Pw_log'  is null.");
            }

            var user = _context.Users.Where(x => x.user_id == changePasswordUser.user_id).FirstOrDefault();

#pragma warning disable CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.
            string password = changePasswordUser.new_user_pw;
#pragma warning restore CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.
#pragma warning disable CS8604 // 가능한 null 참조 인수입니다.
            string? result = PasswordHasher.HashPassword(password);
#pragma warning restore CS8604 // 가능한 null 참조 인수입니다.

#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
            user.user_pw = result;
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.
            user.pw_update_date = DateTime.Now;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            PwLog pw_log = new PwLog();
            pw_log.user_idx = user.idx;
            pw_log.user_id = user.user_id;
            pw_log.user_pw = result;
            _context.Pw_log.Add(pw_log);
            await _context.SaveChangesAsync();

            TempData["success"] = "Password has successfully changed.";
            return RedirectToAction(nameof(SignIn));
        }

        public IActionResult VerifyUserId(string user_id)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            var user = _context.Users.Where(x => x.user_id == user_id).FirstOrDefault();
            if (user != null)
            {
                return Json($"Id {user_id} is already in use.");
            }

            return Json(true);
        }

        public IActionResult VerifyEmail(string email)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            var user = _context.Users.Where(x => x.email == email).FirstOrDefault();
            if (user != null)
            {
                return Json($"Email {email} is already in use.");
            }

            return Json(true);
        }

        public IActionResult VerifyExistEmail(string email)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            var user = _context.Users.Where(x => x.email == email).FirstOrDefault();
            if (user == null)
            {
                return Json($"Email {email} is not exist.");
            }

            return Json(true);
        }

        public IActionResult VerifySignInUserId(string user_id)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            var user = _context.Users.Where(x => x.user_id == user_id).FirstOrDefault();
            if (user == null)
            {
                return Json($"Id {user_id} is not exist.");
            }

            return Json(true);
        }

        public IActionResult VerifySignIn(string user_id, string user_pw)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            var user = _context.Users.Where(x => x.user_id == user_id).FirstOrDefault();
            if (user == null)
            {
                return Json($"Id {user_id} is not exist.");
            }

            if (user.user_pw == null)
            {
                return Json($"Password {user_pw} is not exist.");
            }

            string password = user.user_pw;
            var right = PasswordHasher.VerifyHashedPassword(user_pw, password);

            if (right == false)
            {
                return Json($"Password is incorrect.");
            }

            return Json(true);
        }

        public IActionResult VerifyExistPassword(string user_id, string new_user_pw)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            if (_context.Pw_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Pw_log'  is null.");
            }

            var user = _context.Users.Where(x => x.user_id == user_id).FirstOrDefault();
            if (user == null)
            {
                return Json($"Id {user_id} is not exist.");
            }

            var pw_logs = _context.Pw_log.Where(x => x.user_id == user_id).OrderByDescending(x => x.create_date).Take(3);

            var isExist = 0;

            foreach(var pw in pw_logs)
            {
                if(pw.user_pw == null)
                {
                    continue;
                }

                System.Diagnostics.Trace.WriteLine("[출력할 내용]");
                System.Diagnostics.Trace.WriteLine(new_user_pw);

                var right = PasswordHasher.VerifyHashedPassword(new_user_pw, pw.user_pw);

                if(right == true)
                {
                    isExist++;
                }
            }

            if (isExist > 0)
            {
                return Json($"You cannot use the password you used before.");
            }

            return Json(true);
        }

        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync();
            return Redirect("/Users/SignIn");
        }

        public IActionResult ChangeCulture(string culture)
        {
            Response.Cookies.Append(CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) });

            return Json(true);
        }
    }
}
