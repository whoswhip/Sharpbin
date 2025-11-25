using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Migrations
{
    /// <inheritdoc />
    public partial class GrammarFix : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Visiblity",
                table: "Pastes",
                newName: "Visibility");

            migrationBuilder.RenameIndex(
                name: "IX_Pastes_Visiblity",
                table: "Pastes",
                newName: "IX_Pastes_Visibility");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Visibility",
                table: "Pastes",
                newName: "Visiblity");

            migrationBuilder.RenameIndex(
                name: "IX_Pastes_Visibility",
                table: "Pastes",
                newName: "IX_Pastes_Visiblity");
        }
    }
}
