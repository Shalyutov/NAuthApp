using Newtonsoft.Json;

namespace NAuthApp.Models
{
    public class Account
    {
        [JsonProperty("guid")]
        public string Id { get; set; }
        [JsonProperty("username")]
        public string Username { get; set; }
        [JsonProperty("name")]
        public string Name { get; set; }
        [JsonProperty("email")]
        public string Email { get; set; }
        [JsonProperty("surname")]
        public string Surname { get; set; }
        [JsonProperty("phone")]
        public ulong Phone { get; set; }
        [JsonProperty("LastName")]
        public string LastName { get; set; }
        [JsonProperty("gender")]
        public string Gender { get; set; }

        public Account(string id, string name, string email, string surname, ulong phone, string lastName, string gender, string username)
        {
            Id = id;
            Name = name;
            Email = email;
            Surname = surname;
            Phone = phone;
            LastName = lastName;
            Gender = gender;
            Username = username;
        }
    }
}
