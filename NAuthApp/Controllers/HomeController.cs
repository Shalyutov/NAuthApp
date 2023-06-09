﻿using Microsoft.AspNetCore.Mvc;
using NAuthApp.Models;
using System.Diagnostics;

namespace NAuthApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Route("/b2b")]
        public IActionResult B2B()
        {
            return View();
        }

        [Route("/help")]
        public IActionResult Help()
        {
            return View();
        }
    }
}