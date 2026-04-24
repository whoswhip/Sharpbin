using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class RenameCommentSizes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "TrueSize",
                table: "Comments",
                newName: "StoredSize");

            migrationBuilder.RenameColumn(
                name: "Size",
                table: "Comments",
                newName: "OriginalSize");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "StoredSize",
                table: "Comments",
                newName: "TrueSize");

            migrationBuilder.RenameColumn(
                name: "OriginalSize",
                table: "Comments",
                newName: "Size");
        }
    }
}
