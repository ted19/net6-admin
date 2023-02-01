using Microsoft.AspNetCore.Mvc;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace webAdmin.ViewModels
{
    public class User
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Id")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 4)]
        [RegularExpression(@"^[a-zA-Z]*$", ErrorMessage = "Please enter a valid id")]
        [Remote(action: "VerifyUserId", controller: "Users")]
        public string? user_id { get; set; }

        [Required]
        [DisplayName("Password")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 8)]
        [RegularExpression(@"^(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$", ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        public string? user_pw { get; set; }

        [Required]
        [DisplayName("Re-enter password")]
        [Compare("user_pw", ErrorMessage = "The password you entered does not match.")]
        [DataType(DataType.Password)]
        [NotMapped]
        public string? user_pw_confirm { get; set; }

        [Required]
        [DisplayName("Name")]
        public string? name { get; set; }

        [Required]
        [DisplayName("Department")]
        public string? dept { get; set; }

        [Required]
        [DisplayName("Email")]
        [RegularExpression(@"^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$", ErrorMessage = "Please enter a valid email address.")]
        [Remote(action: "VerifyEmail", controller: "Users")]
        public string? email { get; set; }

        public int status { get; set; } = 0;

        public DateTime create_date { get; set; } = DateTime.Now;

        [DisplayName("Recent password change date")]
        public DateTime pw_update_date { get; set; } = DateTime.Now;

        public int pw_error_count { get; set; } = 0;

        public int users_group_idx { get; set; }

        [NotMapped]
        [DisplayName("Authority group")]
        public string? users_group_name { get; set; }

        [NotMapped]
        [DisplayName("Status")]
        public string? status_name { get; set; }

        [NotMapped]
        [DisplayName("Recent login date")]
        public string? recent_login_date { get; set; }

        [NotMapped]
        [DisplayName("Recent password change date")]
        public string? recent_pw_change_date { get; set; }

        [DisplayName("Blocked reason")]
        public string? block_reason { get; set; } = "none";

        [DisplayName("Blocked date")]
        public DateTime? block_date { get; set; }

        [NotMapped]
        [DisplayName("Blocked date")]
        public string? blocked_date { get; set; }
    }

    public class PwLog
    {
        [Key]
        public int idx { get; set; }

        [Required]
        public int? user_idx { get; set; }

        [Required]
        public string? user_id { get; set; }

        [Required]
        public string? user_pw { get; set; }

        public DateTime create_date { get; set; } = DateTime.Now;
    }

    public class SignIn
    {
        [Required]
        [DisplayName("Id")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 4)]
        [RegularExpression(@"^[a-zA-Z]*$", ErrorMessage = "Please enter a valid id")]
        [Remote(action: "VerifySignInUserId", controller: "Users")]
        public string? user_id { get; set; }

        [Required]
        [DisplayName("Password")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 8)]
        [RegularExpression(@"^(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$", ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        //[Remote(action: "VerifySignIn", controller: "Users", AdditionalFields = nameof(user_id) + "," + nameof(user_pw))]
        public string? user_pw { get; set; }
    }

    public class ResetPassword
    {
        [Required]
        [DisplayName("Email")]
        [RegularExpression(@"^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$", ErrorMessage = "Please enter a valid email address.")]
        [Remote(action: "VerifyExistEmail", controller: "Users")]
        public string? email { get; set; }
    }

    public class ChangePassword
    {
        [Required]
        [DisplayName("Id")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 4)]
        [RegularExpression(@"^[a-zA-Z]*$", ErrorMessage = "Please enter a valid id")]
        [Remote(action: "VerifySignInUserId", controller: "Users")]
        public string? user_id { get; set; }

        [Required]
        [DisplayName("Current password")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 8)]
        [RegularExpression(@"^(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$", ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        [Remote(action: "VerifySignIn", controller: "Users", AdditionalFields = nameof(user_id) + "," + nameof(user_pw))]
        public string? user_pw { get; set; }

        [Required]
        [DisplayName("New password")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 8)]
        [RegularExpression(@"^(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$", ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        [Remote(action: "VerifyExistPassword", controller: "Users", AdditionalFields = nameof(user_id) + "," + nameof(new_user_pw))]
        [NotMapped]
        public string? new_user_pw { get; set; }

        [Required]
        [DisplayName("Re-enter new password")]
        [Compare("new_user_pw", ErrorMessage = "The password you entered does not match.")]
        [DataType(DataType.Password)]
        [NotMapped]
        public string? new_user_pw_confirm { get; set; }
    }
}