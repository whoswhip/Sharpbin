using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class UserGrammarFix : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_UID",
                table: "Users");

            migrationBuilder.RenameColumn(
                name: "Visiblity",
                table: "Users",
                newName: "Visibility");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Visibility",
                table: "Users",
                newName: "Visiblity");

            migrationBuilder.CreateIndex(
                name: "IX_Users_UID",
                table: "Users",
                column: "UID",
                unique: true);
        }
    }
}
