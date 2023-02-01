using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using System.Data.Entity;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using webAdmin.Data;
using webAdmin.ViewModels;

namespace webAdmin.Controllers
{
    public abstract class ControllerBase : Controller
    {
        private readonly ILogger<ControllerBase> _logger;
        private readonly ApplicationDbContext _context;

        public ControllerBase(ApplicationDbContext context, ILogger<ControllerBase> logger)
        {
            _context = context;
            _logger = logger;
        }

        public string BaseGetUserData()
        {
            var userId = "";
            System.Security.Claims.ClaimsPrincipal user = User;
            if (user.Identity is not null)
            {
                userId = user.Identity.Name;
            }

            if (_context.Users == null)
            {
                return "";
            }

            var userData = _context.Users.Where(x => x.user_id == userId).FirstOrDefault();

            if (userData != null)
            {
                ViewBag.name = userData.name;
                ViewBag.user_id = userData.user_id;
                ViewBag.dept = userData.dept;
            }

            ViewBag.culture = Request.Cookies[CookieRequestCultureProvider.DefaultCookieName];

            return System.Text.Json.JsonSerializer.Serialize(userData);
        }

        public string AuthCheck(string? action = null)
        {
            var userId = "";
            System.Security.Claims.ClaimsPrincipal user = User;
            if (user.Identity is not null)
            {
                userId = user.Identity.Name;
            }

            if (_context.Users == null)
            {
                return "";
            }

            var userData = _context.Users.Where(x => x.user_id == userId).FirstOrDefault();

            string result = "";

#pragma warning disable CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.
#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
            string controller = ControllerContext.RouteData.Values["controller"].ToString();
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.
#pragma warning restore CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.

            if (action == null)
            {
#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
                action = ControllerContext.RouteData.Values["action"].ToString();
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.
            }

            if (_context.Users_group_menu == null)
            {
                return "";
            }

            if(userData == null)
            {
                return "";
            }

            var usersGroupMenuData = _context.Users_group_menu.Where(x => x.users_group_idx == userData.users_group_idx && x.controller == controller && x.action == action).FirstOrDefault();

            if (usersGroupMenuData == null || usersGroupMenuData.allow_type == null)
            {
                return "";
            }
            else
            {
                result = usersGroupMenuData.allow_type;
            }

            return result;

            //RedirectToRoute(new { controller = "Home", action = "NotAuth" });
        }

        public class LogActionAttribute : Attribute, IActionFilter
        {
            private readonly ILogger<ControllerBase> _logger;
            private readonly ApplicationDbContext _context;
            private readonly JsonSerializerOptions _settings;

            public LogActionAttribute(ApplicationDbContext context, ILogger<ControllerBase> logger)
            {
                _context = context;
                _logger = logger;

                TextEncoderSettings encoderSettings = new();
                encoderSettings.AllowRange(UnicodeRanges.All);

                JsonSerializerOptions settings = new()
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(encoderSettings),
                    AllowTrailingCommas = true
                };

                _settings = settings;
            }

            public void OnActionExecuting(ActionExecutingContext context)
            {
                var controller = ((ControllerBase)context.Controller).ControllerContext.ActionDescriptor.ControllerName;
                var action = ((ControllerBase)context.Controller).ControllerContext.ActionDescriptor.ActionName;

                StringBuilder sb = new StringBuilder();
                sb.Append(System.Text.Json.JsonSerializer.Serialize(context.ActionArguments, _settings));
                context.HttpContext.Items["LogRequestBody"] = sb;
                context.HttpContext.Items["BeforeData"] = BeforeData(controller, action, context);
                // Do something before the action executes.
            }

            public void OnActionExecuted(ActionExecutedContext context)
            {
                // Do something after the action executes.

#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
                var requestBody = context.HttpContext.Items["LogRequestBody"] != null ? context.HttpContext.Items["LogRequestBody"].ToString() : "";
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.
                _logger.LogInformation("LOG requestBody {0}", requestBody);
                
                context.HttpContext.Items.Remove("LogRequestBody");

#pragma warning disable CS8602 // null 가능 참조에 대한 역참조입니다.
                var beforeData = context.HttpContext.Items["BeforeData"] != null ? context.HttpContext.Items["BeforeData"].ToString() : "";
#pragma warning restore CS8602 // null 가능 참조에 대한 역참조입니다.
                context.HttpContext.Items.Remove("BeforeData");

                var controller = ((ControllerBase)context.Controller).ControllerContext.ActionDescriptor.ControllerName;
                var action = ((ControllerBase)context.Controller).ControllerContext.ActionDescriptor.ActionName;

#pragma warning disable CS8600 // null 리터럴 또는 가능한 null 값을 null을 허용하지 않는 형식으로 변환하는 중입니다.
                IPAddress remoteIpAddress = context.HttpContext.Connection.RemoteIpAddress;
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

                var admin = context.HttpContext.User;

                var userId = "";

                if (admin.Identity is not null)
                {
                    userId = admin.Identity.Name;
                }

                if (_context.Users != null)
                {
                    var userData = _context.Users.Where(x => x.user_id == userId).FirstOrDefault();

                    if (userData != null && _context.Admin_log != null)
                    {
                        AdminLog admin_log = new AdminLog();
                        admin_log.user_idx = userData.idx;
                        admin_log.user_id = userId;
                        admin_log.user_ip = login_ip;
                        admin_log.parameter = requestBody;
                        admin_log.controller = controller.ToString();
                        admin_log.action = action.ToString();
                        admin_log.before_data = beforeData;
                        admin_log.after_data = AfterData(controller, action, requestBody);

                        _context.Admin_log.Add(admin_log);
                        _context.SaveChanges();
                    }
                }
            }

            public string BeforeData(string controller, string action, ActionExecutingContext context)
            {
                var resultData = "";

                if (_context.Users == null || _context.Users_group == null || _context.Admin_group == null ||
                    _context.Users_group_menu == null || _context.Admin_group_menu == null)
                {
                    return "";
                }

                if ((controller == "Admin" && action == "Create") ||
                    (controller == "UsersGroup" && action == "CreateGroup") ||
                    (controller == "UsersGroup" && action == "CreateGroupMenu")
                    )
                {
                    resultData = "{}";
                }
                else if (controller == "Admin" && action == "Edit")
                {
                    var dictionary = context.ActionArguments;

                    var idx = 0;
                    foreach (var key in dictionary.Keys)
                    {
                        var val = dictionary[key];

                        if (key == "id")
                        {
                            idx = Convert.ToInt32(val);
                        }
                    }

                    var result = _context.Users.Where(x => x.idx == idx).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "Admin" && action == "Delete")
                {
                    var dictionary = context.ActionArguments;

                    var idx = 0;
                    foreach (var key in dictionary.Keys)
                    {
                        var val = dictionary[key];

                        if (key == "id")
                        {
                            idx = Convert.ToInt32(val);
                        }
                    }

                    var result = _context.Users.Where(x => x.idx == idx).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "EditGroup")
                {
                    var id = 0;
                    var stringArgs = context.ActionArguments.ToList();

                    foreach (var keyValue in stringArgs)
                    {
                        context.ActionArguments[keyValue.Key] = keyValue.Value;
                    }

#pragma warning disable CS8605 // 가능한 null 값을 unboxing합니다.
                    id = (int)context.ActionArguments["id"];
#pragma warning restore CS8605 // 가능한 null 값을 unboxing합니다.

                    _logger.LogInformation("LOG name {0}", id);

                    var result = _context.Admin_group.Where(x => x.idx == id).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "EditGroupMenu")
                {
                    var id = 0;
                    var stringArgs = context.ActionArguments.ToList();

                    foreach (var keyValue in stringArgs)
                    {
                        context.ActionArguments[keyValue.Key] = keyValue.Value;
                    }

#pragma warning disable CS8605 // 가능한 null 값을 unboxing합니다.
                    id = (int)context.ActionArguments["id"];
#pragma warning restore CS8605 // 가능한 null 값을 unboxing합니다.

                    _logger.LogInformation("LOG name {0}", id);

                    var result = _context.Admin_group_menu.Where(x => x.idx == id).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "DeleteGroup")
                {
                    var dictionary = context.ActionArguments;

                    var idx = 0;
                    foreach (var key in dictionary.Keys)
                    {
                        var val = dictionary[key];

                        if (key == "id")
                        {
                            idx = Convert.ToInt32(val);
                        }
                    }

                    var result = _context.Users_group.Where(x => x.idx == idx).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "DeleteGroupMenu")
                {
                    var dictionary = context.ActionArguments;

                    var idx = 0;
                    foreach (var key in dictionary.Keys)
                    {
                        var val = dictionary[key];

                        if (key == "id")
                        {
                            idx = Convert.ToInt32(val);
                        }
                    }

                    var result = _context.Users_group_menu.Where(x => x.idx == idx).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }

                return resultData;
            }

            public string AfterData(string controller, string action, string? requestBody)
            {
                var resultData = "";

                if (_context.Users == null || _context.Users_group == null || _context.Users_group_menu == null ||
                    _context.Admin_group_menu == null)
                {
                    return "";
                }

                if (controller == "Admin" && action == "Create")
                {
                    var result = _context.Users.OrderByDescending(x => x.idx).Take(1).SingleOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "Admin" && action == "Edit" && requestBody != null)
                {
                    var jsonObject = System.Text.Json.JsonDocument.Parse(requestBody);
                    var id = jsonObject.RootElement.GetProperty("id");

                    var result = _context.Users.Where(x => x.idx == id.GetInt32()).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if ((controller == "Admin" && action == "Delete") ||
                    (controller == "UsersGroup" && action == "DeleteGroup") ||
                    (controller == "UsersGroup" && action == "DeleteGroupMenu"))
                {
                    resultData = "{}";
                }
                else if (controller == "UsersGroup" && action == "CreateGroup")
                {
                    var result = _context.Users_group.OrderByDescending(x => x.idx).Take(1).SingleOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "EditGroup" && requestBody != null)
                {
                    var jsonObject = System.Text.Json.JsonDocument.Parse(requestBody);
                    var id = jsonObject.RootElement.GetProperty("id");

                    var result = _context.Users_group.Where(x => x.idx == id.GetInt32()).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "CreateGroupMenu")
                {
                    var result = _context.Users_group_menu.OrderByDescending(x => x.idx).Take(1).SingleOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }
                else if (controller == "UsersGroup" && action == "EditGroupMenu" && requestBody != null)
                {
                    var jsonObject = System.Text.Json.JsonDocument.Parse(requestBody);
                    var id = jsonObject.RootElement.GetProperty("id");

                    var result = _context.Users_group_menu.Where(x => x.idx == id.GetInt32()).FirstOrDefault();
                    resultData = System.Text.Json.JsonSerializer.Serialize(result, _settings);
                }

                return resultData;
            }
        }
    }
}