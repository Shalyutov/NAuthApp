using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace NAuthApp.Models
{
    public class AuthPair
    {
        [Remote("IsUserExists", "User", HttpMethod = "Get")]
        [Required(ErrorMessage = "Обязательное поле")]
        public string? Username { get; set;}
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Обязательное поле")]
        public string? Password { get; set;}
    }
}
