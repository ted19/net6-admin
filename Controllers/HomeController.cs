using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using webAdmin.Data;
using webAdmin.ViewModels;

namespace webAdmin.Controllers
{
    [Authorize]
    public class HomeController : ControllerBase
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;

        public HomeController(ApplicationDbContext context, ILogger<HomeController> logger) : base(context, logger)
        {
            _context = context;
            _logger = logger;
        }

        public IActionResult Index()
        {
            BaseGetUserData();
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult NoPermission()
        {
            BaseGetUserData();
            var controller = TempData["controller"];

            ViewBag.controller = controller;
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}