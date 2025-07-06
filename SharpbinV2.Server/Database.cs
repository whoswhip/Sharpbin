using BCrypt.Net;
using Microsoft.Data.Sqlite;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV2.Server
{
    public class Database
    {
        public static async Task<User> UserFromUsername(string username)
        {
            if (string.IsNullOrEmpty(username))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE Username = @Username;";
                    command.Parameters.AddWithValue("@Username", username);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new User
                        {
                            UID = reader.GetInt32(0),
                            UUID = reader.GetString(1),
                            Type = reader.GetInt32(2),
                            Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Username = reader.GetString(4),
                            DisplayName = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Password = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            LastLogin = reader.GetInt64(8)
                        };
                    }
                }
            }
        }
        public static async Task<User> UserFromUUID(string uuid)
        {
            if (string.IsNullOrEmpty(uuid))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@UUID", uuid);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new User
                        {
                            UID = reader.GetInt32(0),
                            UUID = reader.GetString(1),
                            Type = reader.GetInt32(2),
                            Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Username = reader.GetString(4),
                            DisplayName = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Password = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            LastLogin = reader.GetInt64(8)
                        };
                    }
                }
            }
        }
        public static async Task<User> UserFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE Email = @Email;";
                    command.Parameters.AddWithValue("@Email", email);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new User
                        {
                            UID = reader.GetInt32(0),
                            UUID = reader.GetString(1),
                            Type = reader.GetInt32(2),
                            Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Username = reader.GetString(4),
                            DisplayName = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Password = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            LastLogin = reader.GetInt64(8)
                        };
                    }
                }
            }
        }
        public static async Task<User> UserFromToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM sessions WHERE Token = @Token;";
                    command.Parameters.AddWithValue("@Token", token);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return await UserFromUUID(reader.GetString(1));
                    }
                }
            }
        }
        public static async Task<int> EnumeratePastes()
        {
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT COUNT(*) FROM pastes;";
                    return Convert.ToInt32(await command.ExecuteScalarAsync());
                }
            }
        }
        public static async Task<int> EnumerateUserPastes(User user)
        {
            if (user == null)
                return 0;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT COUNT(*) FROM pastes WHERE AuthorUUID = @AuthorUUID;";
                    command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                    return Convert.ToInt32(await command.ExecuteScalarAsync());
                }
            }
        }
        public static async Task<Paste> GetPasteFromID(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM pastes WHERE ID = @ID;";
                    command.Parameters.AddWithValue("@ID", id);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new Paste
                        {
                            UUID = reader.GetString(1),
                            ID = reader.GetString(2),
                            Visibility = reader.GetInt32(3),
                            Title = reader.IsDBNull(4) ? null : reader.GetString(4),
                            AuthorUUID = reader.GetString(5),
                            FilePath = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            Edited = reader.GetInt64(8),
                            Size = reader.GetInt32(9),
                            TrueSize = reader.GetInt32(10),
                            Views = reader.GetInt32(11),
                            Syntax = reader.IsDBNull(12) ? null : reader.GetString(12)
                        };
                    }
                }
            }
        }
        public static async Task<bool> HasAlreadyViewedFromRqDetails(RequestDetails details)
        {
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM views WHERE Ip = @Ip AND UserAgent = @UserAgent;";
                    command.Parameters.AddWithValue("@Ip", Bcrypt.HashPassword(details.Ip, Bcrypt.GenerateSalt(8)));
                    command.Parameters.AddWithValue("@UserAgent", details.UserAgent);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        return reader.HasRows;
                    }
                }
            }
        }
        public static async Task<bool> HasAlreadyViewedFromUserDetails(User user)
        {
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM views WHERE UserUUID = @UserUUID;";
                    command.Parameters.AddWithValue("@UserUUID", user.UUID);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        return reader.HasRows;
                    }
                }
            }
        }
        public static async Task AddViewToPaste(User user, Paste paste, RequestDetails details)
        {
            if (paste == null || details == null)
                return;
            var _user = user ?? new User { UUID = "0" };
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "INSERT INTO views (UserUUID, PasteUUID, Ip, UserAgent, Created) VALUES (@UserUUID, @PasteUUID, @Ip, @UserAgent, @Created);";
                    command.Parameters.AddWithValue("@UserUUID", _user.UUID);
                    command.Parameters.AddWithValue("@PasteUUID", paste.UUID);
                    command.Parameters.AddWithValue("@Ip", Bcrypt.HashPassword(details.Ip, Bcrypt.GenerateSalt(8)));
                    command.Parameters.AddWithValue("@UserAgent", details.UserAgent);
                    command.Parameters.AddWithValue("@Created", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    await command.ExecuteNonQueryAsync();
                    command.CommandText = "UPDATE pastes SET Views = Views + 1 WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@UUID", paste.UUID);
                    await command.ExecuteNonQueryAsync();
                }
                await connection.CloseAsync();
            }
        }
        public static async Task<List<Paste>> PastesFromUser(User user)
        {
            if (user == null)
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM pastes WHERE AuthorUUID = @AuthorUUID;";
                    command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        var pastes = new List<Paste>();
                        while (await reader.ReadAsync())
                        {
                            pastes.Add(new Paste
                            {
                                UUID = reader.GetString(1),
                                ID = reader.GetString(2),
                                Visibility = reader.GetInt32(3),
                                Title = reader.IsDBNull(4) ? null : reader.GetString(4),
                                AuthorUUID = reader.GetString(5),
                                FilePath = reader.GetString(6),
                                Created = reader.GetInt64(7),
                                Edited = reader.GetInt64(8),
                                Size = reader.GetInt32(9),
                                TrueSize = reader.GetInt32(10),
                                Views = reader.GetInt32(11),
                                Syntax = reader.IsDBNull(12) ? null : reader.GetString(12)
                            });
                        }
                        return pastes;
                    }
                }
            }
        }

        public static async Task<PasswordReset> GetPasswordReset(string url, string uuid, string token)
        {
            if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(uuid) || string.IsNullOrEmpty(token))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = new SqliteCommand(Program.MainDatabaseConnection))
                {
                    command.CommandText = "SELECT * FROM passwordresets WHERE URL = @URL AND UUID = @UUID AND Token = @Token;";
                    command.Parameters.AddWithValue("@URL", url);
                    command.Parameters.AddWithValue("@UUID", uuid);
                    command.Parameters.AddWithValue("@Token", token);
                    await command.ExecuteNonQueryAsync();
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new PasswordReset
                        {
                            UID = reader.GetString(0),
                            UUID = reader.GetString(1),
                            USERUUID = reader.GetString(2),
                            URL = reader.GetString(3),
                            Token = reader.GetString(4),
                            Created = reader.GetInt64(5),
                            Expirary = reader.GetInt64(6)
                        };
                    }
                }
            }
        }
        public static async Task<bool> ResetPassword(string uuid, string password_hash)
        {
            if (string.IsNullOrEmpty(uuid) || string.IsNullOrEmpty(password_hash))
                return false;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = new SqliteCommand(Program.MainDatabaseConnection))
                {
                    command.CommandText = "UPDATE users SET Password = @Password WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@Password", password_hash);
                    command.Parameters.AddWithValue("@UUID", uuid);
                    await command.ExecuteNonQueryAsync();
                    return true;
                }
            }
        }
    }
}
