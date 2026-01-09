using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class Init : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    UID = table
                        .Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    UUID = table.Column<Guid>(type: "TEXT", nullable: false),
                    Username = table.Column<string>(type: "TEXT", nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", nullable: true),
                    LastLogin = table.Column<long>(type: "INTEGER", nullable: true),
                    Roles = table.Column<string>(type: "TEXT", nullable: false),
                    Visiblity = table.Column<int>(type: "INTEGER", nullable: false),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.UID);
                }
            );

            migrationBuilder.CreateTable(
                name: "Pastes",
                columns: table => new
                {
                    PID = table
                        .Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    UUID = table.Column<string>(type: "TEXT", nullable: false),
                    ID = table.Column<string>(type: "TEXT", nullable: true),
                    Title = table.Column<string>(type: "TEXT", nullable: true),
                    AuthorUUID = table.Column<string>(type: "TEXT", nullable: false),
                    UserUID = table.Column<int>(type: "INTEGER", nullable: true),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    EditedAt = table.Column<long>(type: "INTEGER", nullable: true),
                    Size = table.Column<int>(type: "INTEGER", nullable: false),
                    TrueSize = table.Column<int>(type: "INTEGER", nullable: false),
                    Views = table.Column<int>(type: "INTEGER", nullable: false),
                    Syntax = table.Column<string>(type: "TEXT", nullable: true),
                    Visiblity = table.Column<int>(type: "INTEGER", nullable: false),
                    ExpiresAt = table.Column<long>(type: "INTEGER", nullable: false),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Pastes", x => x.PID);
                    table.ForeignKey(
                        name: "FK_Pastes_Users_UserUID",
                        column: x => x.UserUID,
                        principalTable: "Users",
                        principalColumn: "UID"
                    );
                }
            );

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    UserUUID = table.Column<Guid>(type: "TEXT", nullable: false),
                    Token = table.Column<string>(type: "TEXT", nullable: false),
                    JwtId = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAt = table.Column<long>(type: "INTEGER", nullable: false),
                    Used = table.Column<bool>(type: "INTEGER", nullable: false),
                    UserUID = table.Column<int>(type: "INTEGER", nullable: true),
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.UserUUID);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_Users_UserUID",
                        column: x => x.UserUID,
                        principalTable: "Users",
                        principalColumn: "UID"
                    );
                }
            );

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_AuthorUUID",
                table: "Pastes",
                column: "AuthorUUID"
            );

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_ExpiresAt",
                table: "Pastes",
                column: "ExpiresAt"
            );

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_ID",
                table: "Pastes",
                column: "ID",
                unique: true
            );

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_PID",
                table: "Pastes",
                column: "PID",
                unique: true
            );

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_UserUID",
                table: "Pastes",
                column: "UserUID"
            );

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes",
                column: "UUID",
                unique: true
            );

            migrationBuilder.CreateIndex(name: "IX_Pastes_Views", table: "Pastes", column: "Views");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Visiblity",
                table: "Pastes",
                column: "Visiblity"
            );

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserUID",
                table: "RefreshTokens",
                column: "UserUID"
            );

            migrationBuilder.CreateIndex(
                name: "IX_Users_UID",
                table: "Users",
                column: "UID",
                unique: true
            );

            migrationBuilder.CreateIndex(
                name: "IX_Users_UUID",
                table: "Users",
                column: "UUID",
                unique: true
            );
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "Pastes");

            migrationBuilder.DropTable(name: "RefreshTokens");

            migrationBuilder.DropTable(name: "Users");
        }
    }
}
