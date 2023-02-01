using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace webAdmin.ViewModels
{
    public class Admin
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [Display(Name = "Id")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 4)]
        [RegularExpression(@"^[a-zA-Z]*$", ErrorMessage = "Please enter a valid id")]
        public string? user_id { get; set; }

        [Display(Name = "Password")]
        [StringLength(16, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 8)]
        [RegularExpression(@"^(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$", ErrorMessage = "Please enter a valid password")]
        [DataType(DataType.Password)]
        public string? user_pw { get; set; }

        [Display(Name = "Re-enter password")]
        [Compare("user_pw", ErrorMessage = "The password you entered does not match.")]
        [DataType(DataType.Password)]
        [NotMapped]
        public string? user_pw_confirm { get; set; }

        [Required]
        [Display(Name = "Name")]
        public string? name { get; set; }

        [Required]
        [Display(Name = "Department")]
        public string? dept { get; set; }

        [Required]
        [Display(Name = "Email")]
        [RegularExpression(@"^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$", ErrorMessage = "Please enter a valid email address.")]
        [Remote(action: "VerifyEmail", controller: "Admin", AdditionalFields = nameof(user_id) + "," + nameof(email))]
        public string? email { get; set; }

        [Display(Name = "Status")]
        public int status { get; set; } = 0;

        public DateTime create_date { get; set; } = DateTime.Now;

        [Display(Name = "Recent password change date")]
        public DateTime pw_update_date { get; set; } = DateTime.Now;

        [Display(Name = "Password error count")]
        [Range(0, 100, ErrorMessage = "Password error count must be between 0 and 100 only!!")]
        public int pw_error_count { get; set; } = 0;

        [Display(Name = "Authority group")]
        public int users_group_idx { get; set; }
    }
}