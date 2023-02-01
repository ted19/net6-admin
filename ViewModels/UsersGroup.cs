using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace webAdmin.ViewModels
{
    public class UsersGroup
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Name")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        [Remote(action: "VerifyGroupName", controller: "UsersGroup")]
        public string? name { get; set; }

        [NotMapped]
        public int? group_idx { get; set; }

        public DateTime create_date { get; set; } = DateTime.Now;
    }

    public class AdminGroup
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Name")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        [Remote(action: "VerifyGroupName", controller: "UsersGroup")]
        public string? name { get; set; }

        [NotMapped]
        public int? group_idx { get; set; }

        public DateTime create_date { get; set; } = DateTime.Now;
    }

    public class UsersGroupMenu
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Group idx")]
        public int? users_group_idx { get; set; }

        [Required]
        [DisplayName("Name")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        public string? name { get; set; }

        [Required]
        [DisplayName("Controller")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        public string? controller { get; set; }

        [Required]
        [DisplayName("Action")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        public string? action { get; set; }

        [Required]
        [DisplayName("Allow_type")]
        [StringLength(2, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 1)]
        public string? allow_type { get; set; }

        [NotMapped]
        public List<SelectListItem> allow_types { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "r", Text = "Read" },
            new SelectListItem { Value = "w", Text = "Write" }
        };

        public DateTime create_date { get; set; } = DateTime.Now;
    }

    public class AdminGroupMenu
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Group idx")]
        public int? users_group_idx { get; set; }

        [Required]
        [DisplayName("Name")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        public string? name { get; set; }

        [Required]
        [DisplayName("Controller")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        public string? controller { get; set; }

        [Required]
        [DisplayName("Action")]
        [StringLength(50, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 2)]
        public string? action { get; set; }

        [Required]
        [DisplayName("Allow_type")]
        [StringLength(2, ErrorMessage = "{0} length must be between {2} and {1}.", MinimumLength = 1)]
        public string? allow_type { get; set; }

        [NotMapped]
        public List<SelectListItem> allow_types { get; } = new List<SelectListItem>
        {
            new SelectListItem { Value = "r", Text = "Read" },
            new SelectListItem { Value = "w", Text = "Write" }
        };

        public DateTime create_date { get; set; } = DateTime.Now;
    }
}