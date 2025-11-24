using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Migrations
{
    /// <inheritdoc />
    public partial class AddVisibility : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Type",
                table: "Users",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "Visiblity",
                table: "Users",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "Visiblity",
                table: "Pastes",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Visiblity",
                table: "Pastes",
                column: "Visiblity");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Pastes_Visiblity",
                table: "Pastes");

            migrationBuilder.DropColumn(
                name: "Type",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "Visiblity",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "Visiblity",
                table: "Pastes");
        }
    }
}
