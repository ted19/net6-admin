using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using webAdmin.Data;

namespace webAdmin.ViewModels
{
    public class LoginLog
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Admin idx")]
        public int? user_idx { get; set; }

        [Required]
        [DisplayName("Admin id")]
        public string? user_id { get; set; }

        [Required]
        [DisplayName("Login ip")]
        public string? login_ip { get; set; }

        [DisplayName("Log date")]
        public DateTime log_date { get; set; } = DateTime.Now;

        [Required]
        [DisplayName("Success YN")]
        public string? success_yn { get; set; }
    }

    public class LoginLogDataList
    {
        [Required]
        public int draw { get; set; }

        public string? search_type { get; set; }

        public string? search_value { get; set; }

        [Required]
        public string? search_date { get; set; }

        [Required]
        public int start { get; set; }

        [Required]
        public int length { get; set; }

        public string? column_name { get; set; }

        public string? column_order { get; set; }
    }

    public class AdminLog
    {
        [Key]
        public int idx { get; set; }

        [Required]
        [DisplayName("Admin idx")]
        public int? user_idx { get; set; }

        [Required]
        [DisplayName("Admin id")]        
        public string? user_id { get; set; }

        [Required]
        [DisplayName("User ip")]
        public string? user_ip { get; set; }

        [Required]
        [DisplayName("Controller")]
        public string? controller { get; set; }

        [Required]
        [DisplayName("Action")]
        public string? action { get; set; }

        [Required]
        [DisplayName("Parameter")]
        public string? parameter { get; set; }

        [Required]
        [DisplayName("Before data")]
        public string? before_data { get; set; }

        [Required]
        [DisplayName("After data")]
        public string? after_data { get; set; }

        [Required]
        [DisplayName("Regist date")]
        public DateTime regist_date { get; set; } = DateTime.Now;
    }

    public class AdminLogDataList
    {
        [Required]
        public int draw { get; set; }

        public string? search_type { get; set; }

        public string? search_value { get; set; }

        [Required]
        public string? search_date { get; set; }

        [Required]
        public int start { get; set; }

        [Required]
        public int length { get; set; }

        public string? column_name { get; set; }

        public string? column_order { get; set; }
    }
}