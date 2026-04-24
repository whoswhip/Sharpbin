using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class InteractionsAndComments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Pastes_PID",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_Size",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_Visibility",
                table: "Pastes");

            migrationBuilder.RenameColumn(
                name: "TrueSize",
                table: "Pastes",
                newName: "StoredSize");

            migrationBuilder.RenameColumn(
                name: "Size",
                table: "Pastes",
                newName: "OriginalSize");

            migrationBuilder.AddColumn<long>(
                name: "CommentID",
                table: "Reports",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Comments",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PastePID = table.Column<long>(type: "INTEGER", nullable: false),
                    ParentCommentID = table.Column<long>(type: "INTEGER", nullable: true),
                    Content = table.Column<byte[]>(type: "BLOB", maxLength: 5000, nullable: true),
                    Size = table.Column<long>(type: "INTEGER", nullable: false),
                    TrueSize = table.Column<long>(type: "INTEGER", nullable: false),
                    IsCompressed = table.Column<bool>(type: "INTEGER", nullable: false),
                    UserUUID = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAt = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Comments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Comments_Comments_ParentCommentID",
                        column: x => x.ParentCommentID,
                        principalTable: "Comments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Comments_Pastes_PastePID",
                        column: x => x.PastePID,
                        principalTable: "Pastes",
                        principalColumn: "PID",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Comments_Users_UserUUID",
                        column: x => x.UserUUID,
                        principalTable: "Users",
                        principalColumn: "UUID",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PasteInteractions",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PasteID = table.Column<long>(type: "INTEGER", nullable: false),
                    UserUUID = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasteInteractions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasteInteractions_Pastes_PasteID",
                        column: x => x.PasteID,
                        principalTable: "Pastes",
                        principalColumn: "PID",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CommentInteractions",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CommentID = table.Column<long>(type: "INTEGER", nullable: false),
                    UserUUID = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CommentInteractions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CommentInteractions_Comments_CommentID",
                        column: x => x.CommentID,
                        principalTable: "Comments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Reports_CommentID",
                table: "Reports",
                column: "CommentID");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_StoredSize",
                table: "Pastes",
                column: "StoredSize");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes",
                column: "UUID");

            migrationBuilder.CreateIndex(
                name: "IX_CommentInteractions_CommentID",
                table: "CommentInteractions",
                column: "CommentID");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_ParentCommentID",
                table: "Comments",
                column: "ParentCommentID");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_PastePID",
                table: "Comments",
                column: "PastePID");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_UserUUID",
                table: "Comments",
                column: "UserUUID");

            migrationBuilder.CreateIndex(
                name: "IX_PasteInteractions_PasteID",
                table: "PasteInteractions",
                column: "PasteID");

            migrationBuilder.AddForeignKey(
                name: "FK_Reports_Comments_CommentID",
                table: "Reports",
                column: "CommentID",
                principalTable: "Comments",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Reports_Comments_CommentID",
                table: "Reports");

            migrationBuilder.DropTable(
                name: "CommentInteractions");

            migrationBuilder.DropTable(
                name: "PasteInteractions");

            migrationBuilder.DropTable(
                name: "Comments");

            migrationBuilder.DropIndex(
                name: "IX_Reports_CommentID",
                table: "Reports");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_StoredSize",
                table: "Pastes");

            migrationBuilder.DropIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes");

            migrationBuilder.DropColumn(
                name: "CommentID",
                table: "Reports");

            migrationBuilder.RenameColumn(
                name: "StoredSize",
                table: "Pastes",
                newName: "TrueSize");

            migrationBuilder.RenameColumn(
                name: "OriginalSize",
                table: "Pastes",
                newName: "Size");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_PID",
                table: "Pastes",
                column: "PID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Size",
                table: "Pastes",
                column: "Size");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_UUID",
                table: "Pastes",
                column: "UUID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Visibility",
                table: "Pastes",
                column: "Visibility");
        }
    }
}
