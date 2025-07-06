using Microsoft.Data.Sqlite;
using SharpbinV2.Server.Models;
using Bcrypt = BCrypt.Net.BCrypt;

namespace SharpbinV2.Server.Services
{
    public class DatabaseService
    {
        private readonly string _connectionString;
        public DatabaseService(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=data.db";
        }

        public async Task<User?> UserFromUsername(string username)
        {
            if (string.IsNullOrEmpty(username))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<User?> UserFromUUID(string uuid)
        {
            if (string.IsNullOrEmpty(uuid))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<User?> UserFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<User?> UserFromToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<int> EnumeratePastes()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT COUNT(*) FROM pastes;";
                    return Convert.ToInt32(await command.ExecuteScalarAsync());
                }
            }
        }
        public async Task<int> EnumerateUserPastes(User user)
        {
            if (user == null)
                return 0;
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<Paste?> GetPasteFromID(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<bool> AlreadyViewed(RequestDetails details)
        {
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<bool> HasAlreadyViewedFromUserDetails(User user)
        {
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task AddViewToPaste(User user, Paste paste, RequestDetails details)
        {
            if (paste == null || details == null)
                return;
            var _user = user ?? new User { UUID = "0" };
            using (var connection = new SqliteConnection(_connectionString))
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
        public async Task<List<Paste?>?> PastesFromUser(User user)
        {
            if (user == null)
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
                        var pastes = new List<Paste?>();
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
        public async Task<PasswordReset?> GetPasswordReset(string url, string uuid, string token)
        {
            if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(uuid) || string.IsNullOrEmpty(token))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
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
        public async Task<bool> ResetPassword(string uuid, string password_hash)
        {
            if (string.IsNullOrEmpty(uuid) || string.IsNullOrEmpty(password_hash))
                return false;
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "UPDATE users SET Password = @Password WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@Password", password_hash);
                    command.Parameters.AddWithValue("@UUID", uuid);
                    await command.ExecuteNonQueryAsync();
                    return true;
                }
            }
        }
        public async Task<Session?> CreateSession(User user, RequestDetails details)
        {
            if (user == null || details == null)
                return new Session { UUID = "0" };
            var session = new Session
            {
                UUID = Guid.NewGuid().ToString(),
                UserUUID = user.UUID,
                Token = HelperService.GenerateToken(),
                Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Expirary = DateTimeOffset.UtcNow.AddDays(14).ToUnixTimeSeconds(),
                Ip = Bcrypt.HashPassword(details.Ip, Bcrypt.GenerateSalt(8)),
                UserAgent = details.UserAgent
            };
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "INSERT INTO sessions (UUID, UserUUID, Token, Created, Expirary, Ip, UserAgent) VALUES (@UUID, @UserUUID, @Token, @Created, @Expirary, @Ip, @UserAgent);";
                    command.Parameters.AddWithValue("@UUID", session.UUID);
                    command.Parameters.AddWithValue("@UserUUID", session.UserUUID);
                    command.Parameters.AddWithValue("@Token", session.Token);
                    command.Parameters.AddWithValue("@Created", session.Created);
                    command.Parameters.AddWithValue("@Expirary", session.Expirary);
                    command.Parameters.AddWithValue("@Ip", session.Ip);
                    command.Parameters.AddWithValue("@UserAgent", session.UserAgent);
                    await command.ExecuteNonQueryAsync();
                }
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "UPDATE users SET LastLogin = @LastLogin WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@LastLogin", session.Created);
                    command.Parameters.AddWithValue("@UUID", user.UUID);
                    await command.ExecuteNonQueryAsync();
                }
            }
            return session;
        }
        public async Task<Session?> GetSession(string token)
        {
            if (string.IsNullOrEmpty(token))
                return null;
            using (var connection = new SqliteConnection(_connectionString))
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
                        return new Session
                        {
                            UUID = reader.GetString(0),
                            UserUUID = reader.GetString(1),
                            Token = reader.GetString(2),
                            Created = reader.GetInt64(3),
                            Expirary = reader.GetInt64(4),
                            Ip = reader.GetString(5),
                            UserAgent = reader.GetString(6)
                        };
                    }
                }
            }
        }
        public async Task<bool> DeleteSession(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "DELETE FROM sessions WHERE Token = @Token;";
                    command.Parameters.AddWithValue("@Token", token);
                    await command.ExecuteNonQueryAsync();
                }
                return true;
            }
        }
        public async Task<User?> CreateUser(string username, string email, string password_hash, string uuid)
        {
            if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password_hash))
                return null;
            var user = new User
            {
                UUID = uuid,
                Type = 0,
                Email = email,
                Username = username,
                DisplayName = username,
                Password = password_hash,
                Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                LastLogin = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "INSERT INTO users (UUID, Type, Email, Username, DisplayName, Password, Created, LastLogin) VALUES (@UUID, @Type, @Email, @Username, @DisplayName, @Password, @Created, @LastLogin);";
                    command.Parameters.AddWithValue("@UUID", user.UUID);
                    command.Parameters.AddWithValue("@Type", user.Type);
                    command.Parameters.AddWithValue("@Email", user.Email ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Username", user.Username);
                    command.Parameters.AddWithValue("@DisplayName", user.DisplayName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Password", user.Password);
                    command.Parameters.AddWithValue("@Created", user.Created);
                    command.Parameters.AddWithValue("@LastLogin", user.LastLogin);
                    var result = await command.ExecuteScalarAsync();
                    user.UID = result != null ? Convert.ToInt32(result) : 0;
                }
            }
            return user;
        }
    }
}
