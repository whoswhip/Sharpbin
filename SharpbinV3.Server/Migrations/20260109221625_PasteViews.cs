using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Server.Migrations
{
    /// <inheritdoc />
    public partial class PasteViews : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Pastes_Views",
                table: "Pastes");

            migrationBuilder.CreateTable(
                name: "PasteViews",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PastePID = table.Column<int>(type: "INTEGER", nullable: false),
                    ViewerHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ViewedAt = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasteViews", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasteViews_Pastes_PastePID",
                        column: x => x.PastePID,
                        principalTable: "Pastes",
                        principalColumn: "PID",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PasteViews_PastePID_ViewerHash",
                table: "PasteViews",
                columns: new[] { "PastePID", "ViewerHash" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PasteViews");

            migrationBuilder.CreateIndex(
                name: "IX_Pastes_Views",
                table: "Pastes",
                column: "Views");
        }
    }
}
