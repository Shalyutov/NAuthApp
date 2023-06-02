using System.Security.Claims;

namespace NAuthApp.Helpers
{
    public class ClaimHelper
    {
        public static string SwitchClaims(string claim)
        {
            return claim switch
            {
                "surname" => ClaimTypes.Surname,
                "name" => ClaimTypes.Name,
                "email" => ClaimTypes.Email,
                "phone" => ClaimTypes.MobilePhone,
                "gender" => ClaimTypes.Gender,
                ClaimTypes.Surname => "surname",
                ClaimTypes.Name => "name",
                ClaimTypes.Email => "email",
                ClaimTypes.MobilePhone => "phone",
                ClaimTypes.Gender => "gender",
                _ => claim
            };
        }
    }
}
