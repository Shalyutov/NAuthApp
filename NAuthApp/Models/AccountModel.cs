using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace NAuthApp.Models
{
    public class AccountModel
    {
        [Remote("IsUserReady", "User", ErrorMessage = "Логин уже занят другим пользователем")]
        [StringLength(32, ErrorMessage = "Значение слишком длинное")]
        [Required(ErrorMessage = "Это поле обязательно для заполнения")]
        public string? Username { get; set; }
        [StringLength(64, ErrorMessage = "Количество символов должно быть от 8 до 64", MinimumLength = 8)]
        [Required(ErrorMessage = "Это поле обязательно для заполнения")]
        [DataType(DataType.Password)]
        public string? Password { get; set; }
        [StringLength(64, ErrorMessage = "Количество символов должно быть от 8 до 64", MinimumLength = 8)]
        [Required(ErrorMessage = "Это поле обязательно для заполнения")]
        [Compare("Password", ErrorMessage = "Пароли не сопадают")]
        [DataType(DataType.Password)]
        public string? Confirm { get; set; }
        [StringLength(128, ErrorMessage = "Значение слишком длинное")]
        [DefaultValue("")]
        public string? Name { get; set; }
        [StringLength(128, ErrorMessage = "Значение слишком длинное")]
        [EmailAddress]
        [DefaultValue("")]
        public string? Email { get; set; }
        [StringLength(128, ErrorMessage = "Значение слишком длинное")]
        [DefaultValue("")]
        public string? Surname { get; set; }
        [DefaultValue(0)]
        public ulong Phone { get; set; }
        [StringLength(128, ErrorMessage = "Значение слишком длинное")]
        [DefaultValue("")]
        public string? LastName { get; set; }
        [StringLength(32, ErrorMessage = "Значение слишком длинное")]
        [DefaultValue("")]
        public string? Gender { get; set; }
    }
}
