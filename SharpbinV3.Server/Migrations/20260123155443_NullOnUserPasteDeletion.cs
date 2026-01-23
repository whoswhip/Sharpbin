using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class NullOnUserPasteDeletion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Reports_Pastes_PastePID",
                table: "Reports");

            migrationBuilder.DropForeignKey(
                name: "FK_Reports_Users_UserUUID",
                table: "Reports");

            migrationBuilder.AddForeignKey(
                name: "FK_Reports_Pastes_PastePID",
                table: "Reports",
                column: "PastePID",
                principalTable: "Pastes",
                principalColumn: "PID",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_Reports_Users_UserUUID",
                table: "Reports",
                column: "UserUUID",
                principalTable: "Users",
                principalColumn: "UUID",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Reports_Pastes_PastePID",
                table: "Reports");

            migrationBuilder.DropForeignKey(
                name: "FK_Reports_Users_UserUUID",
                table: "Reports");

            migrationBuilder.AddForeignKey(
                name: "FK_Reports_Pastes_PastePID",
                table: "Reports",
                column: "PastePID",
                principalTable: "Pastes",
                principalColumn: "PID");

            migrationBuilder.AddForeignKey(
                name: "FK_Reports_Users_UserUUID",
                table: "Reports",
                column: "UserUUID",
                principalTable: "Users",
                principalColumn: "UUID");
        }
    }
}
