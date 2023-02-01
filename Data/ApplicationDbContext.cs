using Microsoft.EntityFrameworkCore;
using webAdmin.ViewModels;

namespace webAdmin.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Category>? Categories { get; set; }

    public DbSet<User>? Users { get; set; }

    public DbSet<Admin>? Admins { get; set; }

    public DbSet<PwLog>? Pw_log { get; set; }

    public DbSet<UsersGroup>? Users_group { get; set; }

    public DbSet<AdminGroup>? Admin_group { get; set; }

    public DbSet<UsersGroupMenu>? Users_group_menu { get; set; }

    public DbSet<AdminGroupMenu>? Admin_group_menu { get; set; }

    public DbSet<LoginLog>? Login_log { get; set; }

    public DbSet<AdminLog>? Admin_log { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<User>(b =>
        {
            b.ToTable("Users");
        });

        builder.Entity<Admin>(b =>
        {
            b.ToTable("Users", schema: "Admin");
        });

        builder.Entity<PwLog>(b =>
        {
            b.ToTable("Pw_log");
        });

        builder.Entity<UsersGroup>(b =>
        {
            b.ToTable("Users_group");
        });

        builder.Entity<AdminGroup>(b =>
        {
            b.ToTable("Users_group", schema: "Admin_group");
        });

        builder.Entity<UsersGroupMenu>(b =>
        {
            b.ToTable("Users_group_menu");
        });

        builder.Entity<AdminGroupMenu>(b =>
        {
            b.ToTable("Users_group_menu", schema: "Admin_group_menu");
        });

        builder.Entity<LoginLog>(b =>
        {
            b.ToTable("Login_log");
        });

        builder.Entity<AdminLog>(b =>
        {
            b.ToTable("Admin_log");
        });
    }
}