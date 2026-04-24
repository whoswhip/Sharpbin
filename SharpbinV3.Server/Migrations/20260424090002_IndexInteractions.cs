using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class IndexInteractions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PasteInteractions_PasteID",
                table: "PasteInteractions");

            migrationBuilder.DropIndex(
                name: "IX_CommentInteractions_CommentID",
                table: "CommentInteractions");

            migrationBuilder.CreateIndex(
                name: "IX_PasteInteractions_PasteID_Type",
                table: "PasteInteractions",
                columns: new[] { "PasteID", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_PasteInteractions_PasteID_UserUUID",
                table: "PasteInteractions",
                columns: new[] { "PasteID", "UserUUID" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CommentInteractions_CommentID_Type",
                table: "CommentInteractions",
                columns: new[] { "CommentID", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_CommentInteractions_CommentID_UserUUID",
                table: "CommentInteractions",
                columns: new[] { "CommentID", "UserUUID" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PasteInteractions_PasteID_Type",
                table: "PasteInteractions");

            migrationBuilder.DropIndex(
                name: "IX_PasteInteractions_PasteID_UserUUID",
                table: "PasteInteractions");

            migrationBuilder.DropIndex(
                name: "IX_CommentInteractions_CommentID_Type",
                table: "CommentInteractions");

            migrationBuilder.DropIndex(
                name: "IX_CommentInteractions_CommentID_UserUUID",
                table: "CommentInteractions");

            migrationBuilder.CreateIndex(
                name: "IX_PasteInteractions_PasteID",
                table: "PasteInteractions",
                column: "PasteID");

            migrationBuilder.CreateIndex(
                name: "IX_CommentInteractions_CommentID",
                table: "CommentInteractions",
                column: "CommentID");
        }
    }
}
