using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Migrations
{
    /// <inheritdoc />
    public partial class AddPasteIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_Users_UID",
                table: "Users",
                column: "UID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_UUID",
                table: "Users",
                column: "UUID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_AuthorUUID",
                table: "Pastes",
                column: "AuthorUUID");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_ExpiresAt",
                table: "Pastes",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_ID",
                table: "Pastes",
                column: "ID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_PID",
                table: "Pastes",
                column: "PID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes",
                column: "UUID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Views",
                table: "Pastes",
                column: "Views");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_UID",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_UUID",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_AuthorUUID",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_ExpiresAt",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_ID",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_PID",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_Views",
                table: "Pastes");
        }
    }
}
