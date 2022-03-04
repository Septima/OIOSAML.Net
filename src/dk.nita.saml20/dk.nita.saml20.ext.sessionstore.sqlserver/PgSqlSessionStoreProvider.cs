using System;
using System.Configuration;
using System.Diagnostics;
using System.Threading;
using Npgsql;
using NpgsqlTypes;
using dk.nita.saml20.Session;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.ext.sessionstore.sqlserver
{
    /// <summary>
    /// <see cref="ISessionStoreProvider"/> based on Sql Server.
    /// </summary>
    public class PgSqlSessionStoreProvider : ISessionStoreProvider
    {
        private readonly string _connectionString;
        private readonly string _schema;
        private TimeSpan _sessionTimeout;
        private readonly Timer _cleanupTimer;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromSeconds(30);
        private ISessionValueFactory _sessionValueFactory;

        /// <summary>
        /// Default constructor that loads settings from configuration file
        /// </summary>
        public PgSqlSessionStoreProvider()
        {
            _connectionString = ConfigurationManager.ConnectionStrings["oiosaml:PgSqlSessionStoreProvider"]?.ConnectionString ?? throw new InvalidOperationException("The connectionstring \'oiosaml:PgSqlSessionStoreProvider\' must be set when using the PgSqlSessionStoreProvider");
            _schema = ConfigurationManager.AppSettings["oiosaml:PgSqlSessionStoreProvider:Schema"] ?? "public";

            int cleanupIntervalSeconds;
            if (int.TryParse(ConfigurationManager.AppSettings["oiosaml:PgSqlSessionStoreProvider:CleanupIntervalSeconds"], out cleanupIntervalSeconds))
            {
                _cleanupInterval = TimeSpan.FromSeconds(cleanupIntervalSeconds);
            }

            bool disableCleanup;
            if (!(bool.TryParse(ConfigurationManager.AppSettings["oiosaml:PgSqlSessionStoreProvider:DisableCleanup"], out disableCleanup) && disableCleanup))
            {
                _cleanupTimer = new Timer(Cleanup, null, TimeSpan.Zero, Timeout.InfiniteTimeSpan);
            }
        }

        void Cleanup(object state)
        {
            try
            {
                ExecuteSqlCommand(cmd =>
                {
                    cmd.CommandText =
                        $@"delete from {_schema}.session_properties where expires_at_utc < :time;
                            delete from {_schema}.user_associations where session_id not in 
                                (select distinct session_id from {_schema}.session_properties);";
                    cmd.Parameters.Add(":time", NpgsqlDbType.Timestamp).Value = DateTime.UtcNow;
                    cmd.ExecuteNonQuery();
                });
            }
            catch (Exception ex)
            {
                Trace.TraceData(TraceEventType.Warning,
                    $"{nameof(PgSqlSessionStoreProvider)}: Cleanup of sessionstore failed: {ex}");
            }
            finally
            {
                _cleanupTimer.Change(_cleanupInterval, Timeout.InfiniteTimeSpan);
            }
        }

        void ISessionStoreProvider.Initialize(TimeSpan sessionTimeout, ISessionValueFactory sessionValueFactory)
        {
            _sessionTimeout = sessionTimeout;
            _sessionValueFactory = sessionValueFactory;
        }

        void ISessionStoreProvider.SetSessionProperty(Guid sessionId, string key, object value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            var serializedValue = _sessionValueFactory.Serialize(value);

            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
                    $@"DO
                    $$ begin
                    update {_schema}.session_properties set 
                    value = :value
                    where session_id = :sessionId and key = @key;

                    if not found then
                      insert into {_schema}.session_properties (session_id, key, value_type, value, expires_at_utc)
                      values (:sessionId, :key, :valueType, :value, :expiresAtUtc);
                    end if;

                    update {_schema}.session_properties 
                    set expires_at_utc = :expiresAtUtc
                    where session_id = :sessionId;
                    end$$";

                cmd.Parameters.Add(":sessionId", NpgsqlDbType.Uuid).Value = sessionId;
                cmd.Parameters.Add(":key", NpgsqlDbType.Varchar).Value = key;
                cmd.Parameters.Add(":valueType", NpgsqlDbType.Varchar).Value = value.GetType().AssemblyQualifiedName;
                cmd.Parameters.Add(":value", NpgsqlDbType.Varchar).Value = serializedValue;
                cmd.Parameters.Add(":expiresAtUtc", NpgsqlDbType.Timestamp).Value = GetExpiresAtUtc();

                cmd.ExecuteNonQuery();
            });
        }

        private DateTime GetExpiresAtUtc()
        {
            return DateTime.UtcNow + _sessionTimeout;
        }

        void ISessionStoreProvider.RemoveSessionProperty(Guid sessionId, string key)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
                    $@"delete from {_schema}.session_properties
                    where session_id = :sessionId and key = :key;

                    update {_schema}.session_properties 
                    set expires_at_utc = :expiresAtUtc
                    where session_id = :sessionId;";

                cmd.Parameters.Add(":sessionId", NpgsqlDbType.Uuid).Value = sessionId;
                cmd.Parameters.Add(":key", NpgsqlDbType.Varchar).Value = key;
                cmd.Parameters.Add(":expiresAtUtc", NpgsqlDbType.Timestamp).Value = GetExpiresAtUtc();

                cmd.ExecuteNonQuery();
            });
        }

        object ISessionStoreProvider.GetSessionProperty(Guid sessionId, string key)
        {
            return ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
                    $@"update {_schema}.session_properties 
                    set expires_at_utc = :expiresAtUtc
                    where session_id = :sessionId;

                    select value_type, value from {_schema}.session_properties
                    where session_id = :sessionId and key = :key;";

                cmd.Parameters.Add(":sessionId", NpgsqlDbType.Uuid).Value = sessionId;
                cmd.Parameters.Add(":key", NpgsqlDbType.Varchar).Value = key;
                cmd.Parameters.Add(":expiresAtUtc", NpgsqlDbType.Timestamp).Value = GetExpiresAtUtc();

                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {

                        var valueType = (string) reader["value_type"];
                        var value = (string) reader["value"];

                        var type = Type.GetType(valueType);

                        if (type != null && value != null)
                        {
                            return _sessionValueFactory.Deserialize(type, value);
                        }
                    }
                }

                return null;
            });
        }

        void ISessionStoreProvider.AssociateUserIdWithSessionId(string userId, Guid sessionId)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
                    $@"DO
                    $$begin
                    if not exists (select * from {_schema}.user_associations where session_id = :sessionId and user_id = :userId) then
                        insert into {_schema}.user_associations (session_id, user_id) values (:sessionId, :userId);
                    end if;
                    end$$";

                cmd.Parameters.Add(":sessionId", NpgsqlDbType.Uuid).Value = sessionId;
                cmd.Parameters.Add(":userId", NpgsqlDbType.Varchar).Value = userId;

                cmd.ExecuteNonQuery();
            });
        }

        void ISessionStoreProvider.AbandonSessionsAssociatedWithUserId(string userId)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
                    $@"delete from {_schema}.session_properties where session_id in (select session_id from {_schema}.user_associations where user_id = :userId);
                    delete from {_schema}.user_associations where user_id = :userId";
                cmd.Parameters.Add(":userId", NpgsqlDbType.Varchar).Value = userId;

                //cmd.Parameters.AddWithValue("@userId", userId);

                cmd.ExecuteNonQuery();
            });
        }

        bool ISessionStoreProvider.DoesSessionExists(Guid sessionId)
        {
            return ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
                    $@"select session_id from {_schema}.session_properties
                    where session_id = :sessionId limit 1;

                    update {_schema}.session_properties 
                    set expires_at_utc = :expiresAtUtc
                    where session_id = :sessionId;";
                cmd.Parameters.Add(":sessionId", NpgsqlDbType.Uuid).Value = sessionId;
                cmd.Parameters.Add(":expiresAtUtc", NpgsqlDbType.Timestamp).Value = GetExpiresAtUtc();

                var any = cmd.ExecuteScalar();
                return any != null;
            });
        }

        void ExecuteSqlCommand(Action<NpgsqlCommand> block)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Open();

                var cmd = conn.CreateCommand();
                block(cmd);
            }
        }

        T ExecuteSqlCommand<T>(Func<NpgsqlCommand, T> block)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Open();

                var cmd = conn.CreateCommand();
                return block(cmd);
            }
        }
    }
}