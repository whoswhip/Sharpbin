using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SharpbinV3.Migrations
{
    /// <inheritdoc />
    public partial class ImprovePastes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FilePath",
                table: "Pastes");

            migrationBuilder.AddColumn<byte[]>(
                name: "Data",
                table: "Pastes",
                type: "BLOB",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddColumn<bool>(
                name: "IsCompressed",
                table: "Pastes",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Data",
                table: "Pastes");

            migrationBuilder.DropColumn(
                name: "IsCompressed",
                table: "Pastes");

            migrationBuilder.AddColumn<string>(
                name: "FilePath",
                table: "Pastes",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }
    }
}
