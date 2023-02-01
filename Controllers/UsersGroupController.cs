using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using webAdmin.Data;
using webAdmin.ViewModels;

namespace webAdmin.Controllers
{
    [Authorize]
    public class UsersGroupController : ControllerBase
    {
        private readonly ILogger<UsersGroupController> _logger;
        private readonly ApplicationDbContext _context;

        public UsersGroupController(ApplicationDbContext context, ILogger<UsersGroupController> logger) : base(context, logger)
        {
            _context = context;
            _logger = logger;
        }

        [HttpGet("/AuthorityGroup")]
        public IActionResult Index()
        {
            BaseGetUserData();
            ViewBag.controller = "AuthorityGroup";
            string auth = AuthCheck();

            if (auth == "")
            {
                TempData["controller"] = "AuthorityGroup";
                return RedirectToAction("NoPermission", "Home");
            }

            return View();
        }

        public async Task<IActionResult> UsersGroupList()
        {
            return _context.Users_group != null ?
                View(await _context.Users_group.ToListAsync()) :
                Problem("Entity set 'ApplicationDbContext.Users_group'  is null.");
        }

        public IActionResult UsersGroupForm()
        {
            return View();
        }

        // POST: UsersGroup/CreateGroup
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [TypeFilter(typeof(LogActionAttribute))]
        public async Task<JsonResult> CreateGroup([Bind("idx,name,creat_date,group_idx")] UsersGroup users_group)
        {
            string auth = AuthCheck();

            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "AuthorityGroup";
                return Json(new { status = "error", message = "No permission" });
            }

            if (ModelState.IsValid)
            {
                _context.Add(users_group);
                _context.SaveChanges();
                //TempData["success"] = "Group created successfully";
                //return RedirectToAction(nameof(Index));
                var lastinsertedId = users_group.idx;
                var groupIdx = users_group.group_idx;

                if (groupIdx > 0)
                {
                    if (_context.Users_group_menu != null)
                    {
                        var fromUsersGroupMenu = _context.Users_group_menu.Where(x => x.users_group_idx == groupIdx);
                    
                        foreach (var item in fromUsersGroupMenu)
                        {
                            UsersGroupMenu toUsersGroupMenu = new UsersGroupMenu();

                            toUsersGroupMenu.users_group_idx = lastinsertedId;
                            toUsersGroupMenu.name = item.name;
                            toUsersGroupMenu.controller = item.controller;
                            toUsersGroupMenu.action = item.action;
                            toUsersGroupMenu.allow_type = item.allow_type;

                            _context.Add(toUsersGroupMenu);
                        }

                        await _context.SaveChangesAsync();
                    }
                }

                return Json(new { status = "success", message = "Group created successfully" });
            }

            return Json(new { status = "error", message = "Error!" });
        }

        public IActionResult VerifyGroupName(string name)
        {
            if (_context.Users_group == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users_group'  is null.");
            }

            var user = _context.Users_group.Where(x => x.name == name).FirstOrDefault();
            if (user != null)
            {
                return Json($"Name {name} is already in use.");
            }

            return Json(true);
        }

        [HttpGet("/UsersGroup/UsersGroupMenuList/{idx}")]
        public async Task<IActionResult> UsersGroupMenuList(int idx)
        {
            ViewData["UsersGroupIdx"] = idx;

            return _context.Users_group_menu != null ?
                View(await _context.Users_group_menu.Where(x => x.users_group_idx == idx).ToListAsync()) :
                Problem("Entity set 'ApplicationDbContext.Users_group_menu'  is null.");
        }

        public IActionResult UsersGroupMenuForm()
        {
            var model = new UsersGroupMenu();
            model.allow_type = "r";
            return View(model);
        }

        // POST: UsersGroup/CreateGroupMenu
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [TypeFilter(typeof(LogActionAttribute))]
        public async Task<JsonResult> CreateGroupMenu([Bind("idx,users_group_idx,name,controller,action,allow_type,creat_date")] UsersGroupMenu users_group_menu)
        {
            string auth = AuthCheck();
            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "AuthorityGroup";
                return Json(new { status = "error", message = "No permission" });
            }

            if (ModelState.IsValid)
            {
                _context.Add(users_group_menu);
                await _context.SaveChangesAsync();
                return Json(new { status = "success", message = "Group menu created successfully" });
            }

            return Json(new { status = "error", message = "Error!" });
        }

        // POST: UsersGroup/EditGroup/5
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [TypeFilter(typeof(LogActionAttribute))]
        public async Task<IActionResult> EditGroup(int id, [Bind("idx,name,creat_date")] UsersGroup users_group)
        {
            string auth = AuthCheck();
            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "AuthorityGroup";
                return Json(new { status = "error", message = "No permission" });
            }

            if (id != users_group.idx)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(users_group);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!UsersGroupExists(users_group.idx))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return Json(new { status = "success", message = "Group edited successfully" });
            }
            return Json(new { status = "error", message = "Error!" });
        }

        // POST: UsersGroup/EditGroupMenu/5
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [TypeFilter(typeof(LogActionAttribute))]
        public async Task<IActionResult> EditGroupMenu(int id, [Bind("idx,users_group_idx,name,controller,action,allow_type,creat_date")] UsersGroupMenu users_group_menu)
        {
            string auth = AuthCheck();
            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "AuthorityGroup";
                return Json(new { status = "error", message = "No permission" });
            }

            if (id != users_group_menu.idx)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(users_group_menu);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!UsersGroupMenuExists(users_group_menu.idx))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return Json(new { status = "success", message = "Group menu edited successfully" });
            }
            return Json(new { status = "error", message = "Error!" });
        }

        // POST: UsersGroup/DeleteGroup/5
        [HttpPost, ActionName("DeleteGroup")]
        [TypeFilter(typeof(LogActionAttribute))]
        public async Task<IActionResult> DeleteGroupConfirmed(int id)
        {
            string auth = AuthCheck("DeleteGroup");
            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "AuthorityGroup";
                return Json(new { status = "error", message = "No permission" });
            }

            if (_context.Users_group == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users_group'  is null.");
            }
            
            if (_context.Users_group_menu == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users_group_menu'  is null.");
            }

            var usersGroup = await _context.Users_group.FindAsync(id);
            if (usersGroup != null)
            {
                _context.Users_group.Remove(usersGroup);
            }

            var usersGroupMenu = _context.Users_group_menu.Where(x => x.users_group_idx == id);
            _context.Users_group_menu.RemoveRange(usersGroupMenu);

            _context.SaveChanges();

            return Json(new { status = "success", message = "Group deleted successfully" });
        }

        private bool UsersGroupExists(int idx)
        {
            return (_context.Users_group?.Any(e => e.idx== idx)).GetValueOrDefault();
        }

        private bool UsersGroupMenuExists(int idx)
        {
            return (_context.Users_group_menu?.Any(e => e.idx == idx)).GetValueOrDefault();
        }

        // POST: UsersGroup/DeleteGroupMenu/5
        [HttpPost, ActionName("DeleteGroupMenu")]
        [TypeFilter(typeof(LogActionAttribute))]
        public async Task<IActionResult> DeleteGroupMenuConfirmed(int id)
        {
            string auth = AuthCheck("DeleteGroupMenu");
            if (auth == "" || auth == "r")
            {
                TempData["controller"] = "AuthorityGroup";
                return Json(new { status = "error", message = "No permission" });
            }

            if (_context.Users_group_menu == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users_group_menu'  is null.");
            }
            var users_group_menu = await _context.Users_group_menu.FindAsync(id);
            if (users_group_menu != null)
            {
                _context.Users_group_menu.Remove(users_group_menu);
            }

            await _context.SaveChangesAsync();
            return Json(new { status = "success", message = "Menu deleted successfully" });
        }
    }
}
