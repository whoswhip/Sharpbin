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
        public async Task<User?> UserFromUID(int uid)
        {
            if (uid <= 0)
                return null;
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE UID = @UID;";
                    command.Parameters.AddWithValue("@UID", uid);
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
                    command.CommandText = "SELECT * FROM views WHERE Fingerprint = @Fingerprint";
                    command.Parameters.AddWithValue("@Fingerprint", HelperService.SHA256Hash(details.Ip + details.UserAgent, Program.SHA256Salt));
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
                    command.CommandText = "INSERT INTO views (UserUUID, PasteUUID, Fingerprint, UserAgent, Created) VALUES (@UserUUID, @PasteUUID, @Fingerprint, @UserAgent, @Created);";
                    command.Parameters.AddWithValue("@UserUUID", _user.UUID);
                    command.Parameters.AddWithValue("@PasteUUID", paste.UUID);
                    command.Parameters.AddWithValue("@Fingerprint", HelperService.SHA256Hash(details.Ip + details.UserAgent, Program.SHA256Salt));
                    command.Parameters.AddWithValue("@UserAgent", details.UserAgent ?? (object)DBNull.Value);
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
        public async Task<Session?> CreateSession(User user, RequestDetails details, string token)
        {
            if (user == null || details == null)
                return new Session { UUID = "0" };
            var session = new Session
            {
                UUID = Guid.NewGuid().ToString(),
                UserUUID = user.UUID,
                Token = token,
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
                    command.Parameters.AddWithValue("@Email", string.IsNullOrWhiteSpace(user.Email) ? DBNull.Value : user.Email);
                    command.Parameters.AddWithValue("@Username", user.Username);
                    command.Parameters.AddWithValue("@DisplayName", user.DisplayName ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Password", user.Password);
                    command.Parameters.AddWithValue("@Created", user.Created);
                    command.Parameters.AddWithValue("@LastLogin", user.LastLogin);
                    await command.ExecuteNonQueryAsync();
                }
            }
            return user;
        }
        public async Task<bool> DeleteUser(User user)
        {
            if (user == null)
                return false;
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "DELETE FROM users WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@UUID", user.UUID);
                    await command.ExecuteNonQueryAsync();
                }
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "DELETE FROM pastes WHERE AuthorUUID = @AuthorUUID;";
                    command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                    await command.ExecuteNonQueryAsync();
                }
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "DELETE FROM sessions WHERE UserUUID = @UserUUID;";
                    command.Parameters.AddWithValue("@UserUUID", user.UUID);
                    await command.ExecuteNonQueryAsync();
                }
                // anonymize all views by user
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "UPDATE views SET UserUUID = @UserUUID WHERE UserUUID = @OldUserUUID;";
                    command.Parameters.AddWithValue("@UserUUID", "0");
                    command.Parameters.AddWithValue("@OldUserUUID", user.UUID);
                    await command.ExecuteNonQueryAsync();
                }
                return true;
            }
        }
        public async Task<bool> CreatePaste(Paste paste, ILogger logger)
        {
            try
            {
                if (paste == null || string.IsNullOrEmpty(paste.UUID) || string.IsNullOrEmpty(paste.ID) || paste.AuthorUUID == null)
                    return false;
                using (var connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO pastes (UUID, ID, Visibility, Title, AuthorUUID, FilePath, Created, Edited, Size, TrueSize, Views, Syntax) VALUES (@UUID, @ID, @Visibility, @Title, @AuthorUUID, @FilePath, @Created, @Edited, @Size, @TrueSize, @Views, @Syntax);";
                        command.Parameters.AddWithValue("@UUID", paste.UUID);
                        command.Parameters.AddWithValue("@ID", paste.ID);
                        command.Parameters.AddWithValue("@Visibility", paste.Visibility ?? 0);
                        command.Parameters.AddWithValue("@Title", paste.Title ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@AuthorUUID", paste.AuthorUUID);
                        command.Parameters.AddWithValue("@FilePath", paste.FilePath ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Created", paste.Created ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Edited", paste.Edited ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Size", paste.Size ?? 0);
                        command.Parameters.AddWithValue("@TrueSize", paste.TrueSize ?? 0);
                        command.Parameters.AddWithValue("@Views", paste.Views ?? 0);
                        command.Parameters.AddWithValue("@Syntax", paste.Syntax ?? (object)DBNull.Value);
                        await command.ExecuteNonQueryAsync();
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to create paste in database.");
                return false;
            }
        }
        public async Task<List<View?>?> GetViewsFromPaste(string uuid, ILogger logger)
        {
            if (string.IsNullOrEmpty(uuid))
                return null;
            try
            {
                using (var connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM views WHERE PasteUUID = @PasteUUID;";
                        command.Parameters.AddWithValue("@PasteUUID", uuid);
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                                return null;
                            var views = new List<View?>();
                            while (await reader.ReadAsync())
                            {
                                views.Add(new View
                                {
                                    UserUUID = reader.GetString(0),
                                    PasteUUID = reader.GetString(1),
                                    Fingerprint = reader.GetString(2),
                                    UserAgent = reader.GetString(3),
                                    Created = reader.GetInt64(4)
                                });
                            }
                            return views;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to get views from paste in database.");
                return null;
            }
        }
        public async Task<List<Paste?>?> GetPastes(int limit, int page, ILogger logger)
        {
            if (limit <= 0 || page < 0)
                return null;
            try
            {
                using (var connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM pastes WHERE Visibility NOT IN (1,2) ORDER BY Created DESC LIMIT @Limit OFFSET @Offset;";
                        command.Parameters.AddWithValue("@Limit", limit);
                        command.Parameters.AddWithValue("@Offset", limit * page);
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                                return null;
                            var pastes = new List<Paste?>();
                            while (await reader.ReadAsync())
                            {
                                pastes.Add(new Paste
                                {
                                    UID = reader.GetInt32(0),
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
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to get pastes from database.");
                return null;
            }
        }
        public async Task<List<Paste?>?> GetPastesFromUser(User user, int limit, int page, ILogger logger, bool _private = false)
        {
            if (user == null || limit <= 0 || page < 0)
                return null;
            try
            {
                using (var connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        if (_private)
                            command.CommandText = "SELECT * FROM pastes WHERE AuthorUUID = @AuthorUUID ORDER BY Created DESC LIMIT @Limit OFFSET @Offset;";
                        else
                            command.CommandText = "SELECT * FROM pastes WHERE AuthorUUID = @AuthorUUID AND Visibility NOT IN (1,2) ORDER BY Created DESC LIMIT @Limit OFFSET @Offset;";

                        command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                        command.Parameters.AddWithValue("@Limit", limit);
                        command.Parameters.AddWithValue("@Offset", limit * page);

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                                return null;
                            var pastes = new List<Paste?>();
                            while (await reader.ReadAsync())
                            {
                                pastes.Add(new Paste
                                {
                                    UID = reader.GetInt32(0),
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
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to get user pastes from database.");
                return null;
            }
        }
        public async Task<bool> DeletePaste(Paste paste, ILogger logger)
        {
            if (paste == null || string.IsNullOrEmpty(paste.UUID))
                return false;
            try
            {
                using (var connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM pastes WHERE UUID = @UUID;";
                        command.Parameters.AddWithValue("@UUID", paste.UUID);
                        await command.ExecuteNonQueryAsync();
                    }

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM views WHERE PasteUUID = @PasteUUID;";
                        command.Parameters.AddWithValue("@PasteUUID", paste.UUID);
                        await command.ExecuteNonQueryAsync();
                    }

                    if (!string.IsNullOrEmpty(paste.FilePath) && File.Exists(paste.FilePath))
                    {
                        File.Delete(paste.FilePath);
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to delete paste from database.");
                return false;
            }
        }
        public async Task<Paste?> UpdatePasteID(Paste paste, string newId, ILogger logger)
        {
            if (paste == null || string.IsNullOrEmpty(paste.UUID) || string.IsNullOrEmpty(newId))
                return null;
            try
            {
                using (var connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "UPDATE pastes SET ID = @NewID, Fileath = @FilePath WHERE UUID = @UUID;";
                        command.Parameters.AddWithValue("@NewID", newId);
                        command.Parameters.AddWithValue("@FilePath", $"pastes/{newId}" ?? paste.FilePath);
                        command.Parameters.AddWithValue("@UUID", paste.UUID);
                        await command.ExecuteNonQueryAsync();
                    }
                }
                paste.ID = newId;
                paste.FilePath = $"pastes/{newId}";
                return paste;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to update paste ID in database.");
                return null;
            }
        }
    }
}
