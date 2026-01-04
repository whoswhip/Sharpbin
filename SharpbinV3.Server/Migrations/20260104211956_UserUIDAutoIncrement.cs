using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class UserUIDAutoIncrement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE TRIGGER Users_UID_AutoIncrement
                AFTER INSERT ON Users
                BEGIN
                    UPDATE Users
                    SET UID = (
                        SELECT IFNULL(MAX(UID), 0) + 1 FROM Users
                    )
                    WHERE rowid = NEW.rowid AND NEW.UID IS NULL;
                END;
            """, suppressTransaction: true);

        }
        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS Users_UID_AutoIncrement;
            """);
        }
    }
}
