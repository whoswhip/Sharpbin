using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class UserUUIDKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Pastes_Users_UserUID",
                table: "Pastes");

            migrationBuilder.DropForeignKey(
                name: "FK_RefreshTokens_Users_UserUID",
                table: "RefreshTokens");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Users",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_UserUID",
                table: "RefreshTokens");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_UserUID",
                table: "Pastes");

            migrationBuilder.DropColumn(
                name: "UserUID",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "UserUID",
                table: "Pastes");

            migrationBuilder.AlterColumn<int>(
                name: "UID",
                table: "Users",
                type: "INTEGER",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "INTEGER")
                .OldAnnotation("Sqlite:Autoincrement", true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_Users",
                table: "Users",
                column: "UUID");

            migrationBuilder.AddForeignKey(
                name: "FK_Pastes_Users_AuthorUUID",
                table: "Pastes",
                column: "AuthorUUID",
                principalTable: "Users",
                principalColumn: "UUID",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RefreshTokens_Users_UserUUID",
                table: "RefreshTokens",
                column: "UserUUID",
                principalTable: "Users",
                principalColumn: "UUID",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Pastes_Users_AuthorUUID",
                table: "Pastes");

            migrationBuilder.DropForeignKey(
                name: "FK_RefreshTokens_Users_UserUUID",
                table: "RefreshTokens");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Users",
                table: "Users");

            migrationBuilder.AlterColumn<int>(
                name: "UID",
                table: "Users",
                type: "INTEGER",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "INTEGER")
                .Annotation("Sqlite:Autoincrement", true);

            migrationBuilder.AddColumn<int>(
                name: "UserUID",
                table: "RefreshTokens",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "UserUID",
                table: "Pastes",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_Users",
                table: "Users",
                column: "UID");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserUID",
                table: "RefreshTokens",
                column: "UserUID");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_UserUID",
                table: "Pastes",
                column: "UserUID");

            migrationBuilder.AddForeignKey(
                name: "FK_Pastes_Users_UserUID",
                table: "Pastes",
                column: "UserUID",
                principalTable: "Users",
                principalColumn: "UID");

            migrationBuilder.AddForeignKey(
                name: "FK_RefreshTokens_Users_UserUID",
                table: "RefreshTokens",
                column: "UserUID",
                principalTable: "Users",
                principalColumn: "UID");
        }
    }
}
