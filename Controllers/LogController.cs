using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using webAdmin.Data;
using webAdmin.ViewModels;
using System.Linq.Dynamic.Core;
using System.Data.Entity;
using DiffPlex.DiffBuilder;
using DiffPlex;

namespace webAdmin.Controllers
{
    [Authorize]
    public class LogController : ControllerBase
    {
        private readonly ILogger<LogController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly IStringLocalizer<LogController> _localizer;
        private readonly ISideBySideDiffBuilder _diffBuilder;

        public LogController(ApplicationDbContext context, ILogger<LogController> logger, IStringLocalizer<LogController> localizer, ISideBySideDiffBuilder bidiffBuilder) : base(context, logger)
        {
            _context = context;
            _logger = logger;
            _localizer = localizer;
            _diffBuilder = bidiffBuilder;
        }

        // GET: LoginLog
        [HttpGet("/LoginLog")]
        public IActionResult LoginLogList()
        {
            BaseGetUserData();
            ViewBag.controller = "LoginLog";
            string auth = AuthCheck();

            if (auth == "")
            {
                TempData["controller"] = "Log";
                return RedirectToAction("NoPermission", "Home");
            }

            _logger.LogInformation("LOG TEST {0}", auth);

            return View();
        }

        // POST: Log/LoginLogDataList
        [HttpPost]
        public IActionResult LoginLogDataList([Bind("draw,search_type,search_value,search_date,start,length,column_name,column_order")] LoginLogDataList login_log_data_list)
        {
            BaseGetUserData();
            ViewBag.controller = "Log";

            if (login_log_data_list.column_order == null || login_log_data_list.search_date == null)
            {
                return Problem("Entity set 'login_log_data_list'  is null.");
            }

            string[] dates = login_log_data_list.search_date.Split("to");

            string startDay = dates[0].Trim() + " 00:00:00";
            string endDay = dates[1].Trim() + " 23:59:59";

            DateTime startDate = Convert.ToDateTime(startDay);
            DateTime endDate = Convert.ToDateTime(endDay);

            if (_context.Login_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Login_log'  is null.");
            }

            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            int userIdx = 0;
            int dbDataCount = 0;

            List<LoginLog> dbFilterData = new List<LoginLog>();
            string sortTypeStr = login_log_data_list.column_order.ToUpper(); // or DESC
            string? SortColumnName = login_log_data_list.column_name; // Your column name
            int start = login_log_data_list.start;
            int length = login_log_data_list.length;
            int skip = length - start;

            if (login_log_data_list.search_type != null)
            {
                if (login_log_data_list.search_value == null)
                {
                    return Problem("Entity set 'search_value'  is null.");
                }

                if (login_log_data_list.search_type == "user_idx")
                {
                    /*
                    int intTypeNumber = 0;
                    bool canConvert = int.TryParse(login_log_data_list.search_value, out intTypeNumber);

                    if (canConvert == true)
                    {
                        userIdx = Convert.ToInt32(login_log_data_list.search_value);
                    }
                    else
                    {
                        userIdx = 0;
                    }
                    */
                    userIdx = Convert.ToInt32(login_log_data_list.search_value);

                }
                else if (login_log_data_list.search_type == "user_id")
                {
                    var user = _context.Users.Where(x => x.user_id == login_log_data_list.search_value).FirstOrDefault();

                    if (user != null)
                    {
                        userIdx = user.idx;
                    }
                    else
                    {
                        userIdx = 0;
                    }
                }

                dbDataCount = _context.Login_log.Where(x => x.user_idx == userIdx
                    && x.log_date >= Convert.ToDateTime(startDate)
                    && x.log_date <= Convert.ToDateTime(endDate)
                ).Count();

                dbFilterData = _context.Login_log.Where(x => x.user_idx == userIdx
                    && x.log_date >= Convert.ToDateTime(startDate)
                    && x.log_date <= Convert.ToDateTime(endDate)
                ).OrderBy($"{SortColumnName} {sortTypeStr}").Skip(start).Take(length).ToList();
            }
            else
            {
                dbDataCount = _context.Login_log.Where(x => x.log_date >= Convert.ToDateTime(startDate)
                    && x.log_date <= Convert.ToDateTime(endDate)
                ).Count();

                dbFilterData = (from s in _context.Login_log
                                where (s.log_date >= startDate
                                && s.log_date <= endDate)
                                select s).OrderBy($"{SortColumnName} {sortTypeStr}").Skip(start).Take(length).ToList();
            }

            int dbDataTotalCount = _context.Login_log.Count();

            IList<dynamic> data = new List<dynamic>();

            foreach (var item in dbFilterData)
            {
                data.Add(new
                {
                    idx = item.idx,
                    user_idx = item.user_idx,
                    user_id = item.user_id,
                    login_ip = item.login_ip,
                    log_date = item.log_date.ToString("yyyy-MM-dd HH:mm:ss"),
                    success_yn = item.success_yn
                });
            }

            var resultData = new Dictionary<string, object>();

            resultData["recordsTotal"] = dbDataTotalCount;
            resultData["recordsFiltered"] = dbDataCount;
            resultData["data"] = data;
            resultData["draw"] = login_log_data_list.draw;

            _logger.LogInformation("LOG TEST {0}", data);

            return Json(resultData);
        }

        // GET: AdminLog
        [HttpGet("/AdminLog")]
        public IActionResult AdminLogList()
        {
            BaseGetUserData();
            ViewBag.controller = "AdminLog";
            string auth = AuthCheck();

            if (auth == "")
            {
                TempData["controller"] = "Log";
                return RedirectToAction("NoPermission", "Home");
            }

            _logger.LogInformation("LOG TEST {0}", auth);

            return View();
        }

        // POST: Log/AdminLogDataList
        [HttpPost]
        public IActionResult AdminLogDataList([Bind("draw,search_type,search_value,search_date,start,length,column_name,column_order")] AdminLogDataList admin_log_data_list)
        {
            BaseGetUserData();
            ViewBag.controller = "Log";

            if (admin_log_data_list.search_date == null || admin_log_data_list.column_order == null)
            {
                return Problem("Entity set 'admin_log_data_list'  is null.");
            }

            string[] dates = admin_log_data_list.search_date.Split("to");

            string startDay = dates[0].Trim() + " 00:00:00";
            string endDay = dates[1].Trim() + " 23:59:59";

            DateTime startDate = Convert.ToDateTime(startDay);
            DateTime endDate = Convert.ToDateTime(endDay);

            if (_context.Admin_log == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Login_log'  is null.");
            }

            if (_context.Users == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Users'  is null.");
            }

            int userIdx = 0;
            int dbDataCount = 0;
            List<AdminLog> dbFilterData = new List<AdminLog>();
            string sortTypeStr = admin_log_data_list.column_order.ToUpper(); // or DESC
            string? SortColumnName = admin_log_data_list.column_name; // Your column name
            int start = admin_log_data_list.start;
            int length = admin_log_data_list.length;
            int skip = length - start;

            if (admin_log_data_list.search_type != null)
            {
                if (admin_log_data_list.search_value == null)
                {
                    return Problem("Entity set 'search_value'  is null.");
                }

                if (admin_log_data_list.search_type == "user_idx")
                {
                    int intTypeNumber = 0;
                    bool canConvert = int.TryParse(admin_log_data_list.search_value, out intTypeNumber);

                    if (canConvert == true)
                    {
                        userIdx = Convert.ToInt32(admin_log_data_list.search_value);
                    }
                    else
                    {
                        userIdx = 0;
                    }

                }
                else if (admin_log_data_list.search_type == "user_id")
                {
                    var user = _context.Users.Where(x => x.user_id == admin_log_data_list.search_value).FirstOrDefault();

                    if (user != null)
                    {
                        userIdx = user.idx;
                    }
                    else
                    {
                        userIdx = 0;
                    }
                }

                dbDataCount = _context.Admin_log.Where(x => x.user_idx == userIdx
                    && x.regist_date >= Convert.ToDateTime(startDate)
                    && x.regist_date <= Convert.ToDateTime(endDate)
                ).Count();

                dbFilterData = _context.Admin_log.Where(x => x.user_idx == userIdx
                    && x.regist_date >= Convert.ToDateTime(startDate)
                    && x.regist_date <= Convert.ToDateTime(endDate)
                ).OrderBy($"{SortColumnName} {sortTypeStr}").Skip(start).Take(length).ToList();
            }
            else
            {
                dbDataCount = _context.Admin_log.Where(x => x.regist_date >= Convert.ToDateTime(startDate)
                    && x.regist_date <= Convert.ToDateTime(endDate)
                ).Count();

                dbFilterData = (from s in _context.Admin_log
                                where (s.regist_date >= startDate
                                && s.regist_date <= endDate)
                                select s).OrderBy($"{SortColumnName} {sortTypeStr}").Skip(start).Take(length).ToList();
            }

            int dbDataTotalCount = _context.Admin_log.Count();

            IList<dynamic> data = new List<dynamic>();

            foreach (var item in dbFilterData)
            {
                data.Add(new
                {
                    idx = item.idx,
                    user_idx = item.user_idx,
                    user_id = item.user_id,
                    user_ip = item.user_ip,
                    controller = item.controller,
                    action = item.action,
                    regist_date = item.regist_date.ToString("yyyy-MM-dd HH:mm:ss"),
                    detail_view = "<input type='button' class='btn btn-primary btn-sm' id='detail_view' name='detail_view' value='" + _localizer["Detail view"] + "'>"
                });
            }

            var resultData = new Dictionary<string, object>();

            resultData["recordsTotal"] = dbDataTotalCount;
            resultData["recordsFiltered"] = dbDataCount;
            resultData["data"] = data;
            resultData["draw"] = admin_log_data_list.draw;

            _logger.LogInformation("LOG TEST {0}", data);

            return Json(resultData);
        }

        // POST: Log/AdminLogData
        [HttpPost]
        public IActionResult AdminLogData(int idx)
        {
            if (_context.Admin_log == null)
            {
                return Json(new { status = "error", message = $"_context.Admin_log is not exist." });
            }

            var adminLog = _context.Admin_log.Where(x => x.idx == idx).SingleOrDefault();

            if (adminLog == null)
            {
                return Json(new { status = "error", message = $"Admin_log is not exist." });
            }

            string? beforeData = "";
            string? afterData = ""; 

            if (adminLog.before_data != null)
            {
                beforeData = adminLog.before_data;
            }

            if (adminLog.after_data != null)
            {
                afterData = adminLog.after_data;
            }

            var sd = new SideBySideDiffBuilder(new Differ());
            var model = sd.BuildDiffModel(beforeData ?? string.Empty, afterData ?? string.Empty);

            ViewBag.parameter = adminLog.parameter;

            return View(model);
        }
    }
}