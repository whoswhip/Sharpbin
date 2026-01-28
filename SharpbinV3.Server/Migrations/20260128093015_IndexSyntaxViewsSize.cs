using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class IndexSyntaxViewsSize : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Size",
                table: "Pastes",
                column: "Size");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Syntax",
                table: "Pastes",
                column: "Syntax");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Views",
                table: "Pastes",
                column: "Views");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Pastes_Size",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_Syntax",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_Views",
                table: "Pastes");
        }
    }
}
