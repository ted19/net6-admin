using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Localization;
using Newtonsoft.Json;
using System.Data.Entity.Infrastructure;
using System.Text;
using webAdmin.Data;
using webAdmin.Extenstions;
using webAdmin.ViewModels;

namespace webAdmin.Controllers
{
    [Authorize]
    public class AdminController : ControllerBase
    {
        private readonly ILogger<AdminController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly IStringLocalizer<AdminController> _localizer;

        public AdminController(ApplicationDbContext context, ILogger<AdminController> logger, IStringLocalizer<AdminController> localizer) : base(context, logger)
        {
            _context = context;
            _logger = logger;
            _localizer = localizer;
        }

        // GET: Admin
        public IActionResult Index()
        {
            BaseGetUserData();
            ViewBag.controller = "Admin";
            string auth = AuthCheck();

            if (auth == "")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            _logger.LogInformation("LOG TEST {0}", auth);

            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            if (_context.Users_group == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users_group'  is null.");
            }

            var adminList = new List<User>();

            var max = (from s in _context.Users_group
                       orderby s.idx descending
                       select s).First();

            //_logger.LogInformation("LOG TEST {0}", max.idx);

            string[] usersGroups = new string[max.idx + 1];

            foreach (var item in _context.Users_group)
            {
                if (item.name == null)
                {
                    continue;
                }

                usersGroups[item.idx] = item.name;
            }

            if (_context.Login_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Login_log'  is null.");
            }

            var recentLoginLog = (from s in _context.Login_log.AsEnumerable()
                                  group s by s.user_idx into g
                                  select g.OrderByDescending(e => e.log_date).FirstOrDefault() into p
                                  select new
                                  {
                                      user_idx = p.user_idx,
                                      log_date = p.log_date
                                  }).ToList();

            string[] usersRecentLoginLog = new string[_context.Login_log.ToList().Count()];

            foreach (var item in recentLoginLog)
            {
                if (item.user_idx != null) {
                    usersRecentLoginLog[(int)item.user_idx] = item.log_date.ToString("yyyy-MM-dd HH:mm:ss");
                }
            }

            string? blockedDate = "";

            foreach (var item in _context.Users)
            {
                string usersGroupName = usersGroups[item.users_group_idx];
                string usersRecentLoginLogDate = usersRecentLoginLog[item.idx];


                if (item.block_date != null)
                {
                    blockedDate = item.block_date?.ToString("yyyy-MM-dd HH:mm:ss");
                } else
                {
                    blockedDate = _localizer["empty"];
                }

                if (usersRecentLoginLogDate == null)
                {
                    usersRecentLoginLogDate = _localizer["empty"];
                }

                string statusName = "";

                if (usersGroupName == null)
                {
                    usersGroupName = _localizer["none"];
                }

                switch (item.status)
                {
                    case 0:
                        statusName = _localizer["unauthenticated"];
                        break;

                    case 10:
                        statusName = _localizer["authenticated"];
                        break;

                    case 20:
                        statusName = _localizer["withdrawn"];
                        break;

                    case 21:
                        statusName = _localizer["blocked"];
                        break;
                }

                string bloackReason = "";

                if (item.block_reason == null)
                {
                    bloackReason = "";
                } else
                {
                    bloackReason = item.block_reason;
                }

                adminList.Add(new User
                {
                    idx = item.idx,
                    user_id = item.user_id,
                    name = item.name,
                    dept = item.dept,
                    email = item.email,
                    status_name = statusName,
                    users_group_name = usersGroupName,
                    block_reason = _localizer[bloackReason],
                    blocked_date = blockedDate,
                    recent_login_date = usersRecentLoginLogDate,
                    recent_pw_change_date = item.pw_update_date.ToString("yyyy-MM-dd HH:mm:ss")
                });
            }

            return View(adminList);
        }

        // GET: Admin/Create
        public IActionResult Create()
        {
            BaseGetUserData();
            ViewBag.controller = "Admin";
            string auth = AuthCheck();

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            return View();
        }

        // POST: Admin/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [TypeFilter(typeof(LogActionAttribute))]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("idx,user_id,user_pw,user_pw_confirm,name,dept,email,status,pw_update_date,pw_error_count,users_group_idx")] User user)
        {
            string auth = AuthCheck();

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            if (ModelState.IsValid)
            {
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

                _context.Add(user);
                await _context.SaveChangesAsync();

                if (_context.Pw_log == null)
                {
                    return Problem("Entity set 'ApplicationDbContext.Pw_log'  is null.");
                }

                PwLog pw_log = new PwLog();
                pw_log.user_idx = user.idx;
                pw_log.user_id = user.user_id;
                pw_log.user_pw = result;
                _context.Pw_log.Add(pw_log);
                await _context.SaveChangesAsync();

                if (_context.Login_log == null)
                {
                    return Problem("Entity set 'ApplicationDbContext.Login_log'  is null.");
                }

                LoginLog login_log = new LoginLog();
                login_log.user_idx = user.idx;
                login_log.user_id = user.user_id;
                login_log.login_ip = "10.10.10.10";
                login_log.success_yn = "Y";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();

                TempData["success"] = "admin created successfully";

                return RedirectToAction(nameof(Index));
            }

            return View(user);
        }

        // GET: Admin/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            BaseGetUserData();

            ViewBag.controller = "Admin";
            string auth = AuthCheck();

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            if (id == null || _context.Admins == null)
            {
                return NotFound();
            }

            var user = await _context.Admins.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            if (_context.Users_group == null)
            {
                return NotFound();
            }

            var usersGroupList = _context.Users_group.ToList();
            ViewBag.users_group_list = new SelectList((System.Collections.IEnumerable)usersGroupList, "idx", "name", user.users_group_idx);

            ViewBag.status_list = new SelectList(new[]
                {
                    new { Idx="0", Name=_localizer["unauthenticated"] },
                    new { Idx="10", Name=_localizer["authenticated"] },
                    new { Idx="20", Name=_localizer["withdrawn"] },
                    new { Idx="21", Name=_localizer["blocked"] }
                }, "Idx", "Name", user.status);

            return View(user);
        }

        // POST: Admin/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [TypeFilter(typeof(LogActionAttribute))]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int? id, [Bind("idx,user_id,user_pw,user_pw_confirm,name,dept,email,status,pw_error_count,users_group_idx")] Admin admin)
        {
            string auth = AuthCheck();

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            if (id == null || _context.Users == null)
            {
                return NotFound();
            }

            User? user = _context.Users.Where(x => x.idx == id).FirstOrDefault();

            if (user == null || user.user_id == null)
            {
                return NotFound();
            }

            if (admin.user_pw == null)
            {
                admin.user_pw = user.user_pw;
            }
            else
            {
                string password = admin.user_pw;
                var result = PasswordHasher.HashPassword(password);

                admin.user_pw = result;
            }

            if (admin.status != 21)
            {
                user.block_reason = "none";
                user.block_date = null;

                if (_context.Login_log == null)
                {
                    TempData["error"] = "admin modified fail";
                    return View(user);
                }

                LoginLog login_log = new LoginLog();
                login_log.user_idx = user.idx;
                login_log.user_id = user.user_id;
                login_log.login_ip = "10.10.10.10";
                login_log.success_yn = "Y";
                _context.Login_log.Add(login_log);
                await _context.SaveChangesAsync();
            }

            user.user_pw = admin.user_pw;
            user.name = admin.name;
            user.dept = admin.dept;
            user.email = admin.email;
            user.status = admin.status;
            user.users_group_idx = admin.users_group_idx;
            user.pw_error_count = admin.pw_error_count;
            user.pw_update_date = admin.pw_update_date;

            try
            {
                _context.Update(user);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException /* ex */)
            {
                TempData["error"] = "admin modified fail";
                return View(user);
            }

            TempData["success"] = "admin modified successfully";

            //CreateAdminLog(parameter, beforeData, afterData);

            return RedirectToAction(nameof(Index));
        }

        public IActionResult VerifyEmail(string user_id, string email)
        {
            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            var user = _context.Users.Where(x => x.email == email && x.user_id != user_id).FirstOrDefault();
            if (user != null)
            {
                return Json($"Email {email} is already in use.");
            }

            return Json(true);
        }

        private bool AdminExists(int idx)
        {
            return (_context.Users?.Any(e => e.idx == idx)).GetValueOrDefault();
        }

        // GET: Admin/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            BaseGetUserData();
            ViewBag.controller = "Admin";
            string auth = AuthCheck();

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            if (id == null || _context.Admins == null)
            {
                return NotFound();
            }

            var user = await _context.Admins.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        // POST: Admin/Delete/5
        [HttpPost, ActionName("Delete")]
        [TypeFilter(typeof(LogActionAttribute))]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            string auth = AuthCheck("Delete");

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "Admin";
                return RedirectToAction("NoPermission", "Home");
            }

            if (_context.Users == null || _context.Login_log == null || _context.Admin_log == null || _context.Pw_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext'  is null.");
            }
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                _context.Users.Remove(user);
            }

            var loginLog = await _context.Login_log.FindAsync(id);
            if (loginLog != null)
            {
                _context.Login_log.Remove(loginLog);
            }

            var adminLog = await _context.Admin_log.FindAsync(id);
            if (adminLog != null)
            {
                _context.Admin_log.Remove(adminLog);
            }

            var pwLog = await _context.Pw_log.FindAsync(id);
            if (pwLog != null)
            {
                _context.Pw_log.Remove(pwLog);
            }

            await _context.SaveChangesAsync();

            TempData["success"] = "admin deleted successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}