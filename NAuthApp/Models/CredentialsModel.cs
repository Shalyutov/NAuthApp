﻿using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace NAuthApp.Models
{
    public class CredentialsModel
    {
        [Remote("IsUserExists", "User", HttpMethod = "Get",ErrorMessage = "Пользователя не существует")]
        public string? Username { get; set;}
        [DataType(DataType.Password)]
        public string? Password { get; set;}
    }
}