
using Dapper;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Data.Sqlite;
using MySql.Data.MySqlClient;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

const string tenantDBSchemaFilePath = "../sql/tenant/10_schema.sql";
const string initializeScript = "../sql/init.sh";
const string cookieName = "isuports_session";
const string RoleAdmin = "admin";
const string RoleOrganizer = "organizer";
const string RolePlayer = "player";
//const string RoleNone = "none";

// 正しいテナント名の正規表現
Regex tenantNameRegexp = new Regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$");
// 	adminDB *sqlx.DB
// 	sqliteDriverName = "sqlite3"
// )

//// XXX https://github.com/DapperLib/Dapper/issues/818
//// record にいい感じにマッピングされない
//Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.Encoder = null;
});

WebApplication app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    //
}

// app.UseHttpsRedirection();

app.Use(async (context, next) =>
{
    if (context.GetEndpoint()?.Metadata.GetMetadata<CachePrivateAttribute>() is not null)
    {
        context.Response.Headers.CacheControl = new[] { "private" };
    }
    await next(context);
});

// 環境変数を取得する、なければデフォルト値を返す
string getEnv(string key, string defaultValue)
{
    return Environment.GetEnvironmentVariable(key) ?? defaultValue;
}

// 管理用DBに接続する
MySqlConnection connectAdminDB()
{
    var connectionString = $"server={getEnv("ISUCON_DB_HOST", "127.0.0.1")};"
        + $"port={getEnv("ISUCON_DB_PORT", "3306")};"
        + $"user={getEnv("ISUCON_DB_USER", "isucon")};"
        + $"password={getEnv("ISUCON_DB_PASSWORD", "isucon")};"
        + $"database={getEnv("ISUCON_DB_NAME", "isuports")}";
    // XXX
    // config.Net = "tcp"
    // config.ParseTime = true
    // app.Logger.LogInformation($"connectionString: {connectionString}");
    var connection = new MySqlConnection(connectionString);
    connection.Open();
    return connection;
}

// テナントDBのパスを返す
string tenantDBPath(Int64 id)
{
    var tenantDBDir = getEnv("ISUCON_TENANT_DB_DIR", "../tenant_db");
    return Path.Join(tenantDBDir, $"{id}.db");
}

// テナントDBに接続する
SqliteConnection connectToTenantDB(Int64 id)
{
    var p = tenantDBPath(id);
    var connection = new SqliteConnection($"Data Source={p}");
    connection.Open();
    return connection;
}

// テナントDBを新規に作成する
async Task createTenantDB(Int64 id)
{
    var path = tenantDBPath(id);

    var p = Process.Start("sh", new string[] { "-c", $"sqlite3 {path} < {tenantDBSchemaFilePath}" });
    await p.WaitForExitAsync();
    if (p.ExitCode != 0)
    {
        var output = await p.StandardOutput.ReadToEndAsync() + await p.StandardError.ReadToEndAsync();
        throw new Exception($"failed to exec sqlite3 {path} < {tenantDBSchemaFilePath}, out={output}: {p.ExitCode}");
    }
}

// // システム全体で一意なIDを生成する
// func dispenseID(ctx context.Context) (string, error) {
// 	var id int64
// 	var lastErr error
// 	for i := 0; i < 100; i++ {
// 		var ret sql.Result
// 		ret, err := adminDB.ExecContext(ctx, "REPLACE INTO id_generator (stub) VALUES (?);", "a")
// 		if err != nil {
// 			if merr, ok := err.(*mysql.MySQLError); ok && merr.Number == 1213 { // deadlock
// 				lastErr = fmt.Errorf("error REPLACE INTO id_generator: %w", err)
// 				continue
// 			}
// 			return "", fmt.Errorf("error REPLACE INTO id_generator: %w", err)
// 		}
// 		id, err = ret.LastInsertId()
// 		if err != nil {
// 			return "", fmt.Errorf("error ret.LastInsertId: %w", err)
// 		}
// 		break
// 	}
// 	if id != 0 {
// 		return fmt.Sprintf("%x", id), nil
// 	}
// 	return "", lastErr
// }

// // 全APIにCache-Control: privateを設定する
// func SetCacheControlPrivate(next echo.HandlerFunc) echo.HandlerFunc {
// 	return func(c echo.Context) error {
// 		c.Response().Header().Set(echo.HeaderCacheControl, "private")
// 		return next(c)
// 	}
// }

// // Run は cmd/isuports/main.go から呼ばれるエントリーポイントです
// func Run() {
// 	e := echo.New()
// 	e.Debug = true
// 	e.Logger.SetLevel(log.DEBUG)

// 	var (
// 		sqlLogger io.Closer
// 		err       error
// 	)
// 	// sqliteのクエリログを出力する設定
// 	// 環境変数 ISUCON_SQLITE_TRACE_FILE を設定すると、そのファイルにクエリログをJSON形式で出力する
// 	// 未設定なら出力しない
// 	// sqltrace.go を参照
// 	sqliteDriverName, sqlLogger, err = initializeSQLLogger()
// 	if err != nil {
// 		e.Logger.Panicf("error initializeSQLLogger: %s", err)
// 	}
// 	defer sqlLogger.Close()

// 	e.Use(middleware.Logger())
// 	e.Use(middleware.Recover())
// 	e.Use(SetCacheControlPrivate)

// SaaS管理者向けAPI
app.MapPost("/api/admin/tenants/add", tenantsAddHandler).WithMetadata(new CachePrivateAttribute());
app.MapGet("/api/admin/tenants/billing", tenantsBillingHandler);

// 	// テナント管理者向けAPI - 参加者追加、一覧、失格
// 	e.GET("/api/organizer/players", playersListHandler)
// 	e.POST("/api/organizer/players/add", playersAddHandler)
// 	e.POST("/api/organizer/player/:player_id/disqualified", playerDisqualifiedHandler)

// 	// テナント管理者向けAPI - 大会管理
// 	e.POST("/api/organizer/competitions/add", competitionsAddHandler)
// 	e.POST("/api/organizer/competition/:competition_id/finish", competitionFinishHandler)
// 	e.POST("/api/organizer/competition/:competition_id/score", competitionScoreHandler)
// 	e.GET("/api/organizer/billing", billingHandler)
// 	e.GET("/api/organizer/competitions", organizerCompetitionsHandler)

// 	// 参加者向けAPI
// 	e.GET("/api/player/player/:player_id", playerHandler)
// 	e.GET("/api/player/competition/:competition_id/ranking", competitionRankingHandler)
// 	e.GET("/api/player/competitions", playerCompetitionsHandler)

// 	// 全ロール及び未認証でも使えるhandler
// 	e.GET("/api/me", meHandler)

// ベンチマーカー向けAPI
app.MapPost("/initialize", initializeHandler);

// 	e.HTTPErrorHandler = errorResponseHandler

// 	adminDB, err = connectAdminDB()
// 	if err != nil {
// 		e.Logger.Fatalf("failed to connect db: %v", err)
// 		return
// 	}
// 	adminDB.SetMaxOpenConns(10)
// 	defer adminDB.Close()

var port = getEnv("SERVER_APP_PORT", "3000");
app.Urls.Add($"http://*:{port}");
app.Logger.LogInformation($"starting isuports server on : {port} ...");

app.Run();
// }
// // エラー処理関数
// func errorResponseHandler(err error, c echo.Context) {
// 	c.Logger().Errorf("error at %s: %s", c.Path(), err.Error())
// 	var he *echo.HTTPError
// 	if errors.As(err, &he) {
// 		c.JSON(he.Code, FailureResult{
// 			Status: false,
// 		})
// 		return
// 	}
// 	c.JSON(http.StatusInternalServerError, FailureResult{
// 		Status: false,
// 	})
// }

// リクエストヘッダをパースしてViewerを返す
async Task<Viewer> parseViewer(HttpRequest request)
{
    var cookie = request.Cookies[cookieName];

    if (cookie == null)
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, $"cookie {cookieName} is not found");
    }
    var tokenStr = cookie;

    // https://www.scottbrady91.com/c-sharp/pem-loading-in-dotnet-core-and-dotnet
    // https://vcsjones.dev/key-formats-dotnet-3/
    var keyFilename = getEnv("ISUCON_JWT_KEY_FILE", "../public.pem");
    var keysrc = await File.ReadAllTextAsync(keyFilename);
    var keystr = Regex.Replace(keysrc, "-----.+-----", "").Replace("\r", "").Replace("\n", "");
    using var rsa = RSA.Create();
    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(keystr), out _);
    // TODO エラー処理
    // if err != nil {
    //     return nil, fmt.Errorf("error os.ReadFile: keyFilename=%s: %w", keyFilename, err)
    // }

    var token = JwtBuilder.Create()
                         .WithAlgorithm(new RS256Algorithm(rsa))
                         .MustVerifySignature()
                         .Decode<Token>(tokenStr);
    app.Logger.LogInformation(token.ToString());

    if (token == null)
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, "error Jwt Decode.");
    }
    if (string.IsNullOrEmpty(token.Sub))
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, $"invalid token: subject is not found in token: {tokenStr}");
    }


    if (string.IsNullOrEmpty(token.Role))
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, $"invalid token: role is not found: {tokenStr}");
    }

    switch (token.Role)
    {
        case RoleAdmin or RoleOrganizer or RolePlayer:
            break;
        default:
            throw new IsuHttpException(HttpStatusCode.Unauthorized, $"invalid token: invalid role: {tokenStr}");
    }
    // aud は1要素でテナント名がはいっている
    if (token.Aud.Length != 1)
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, $"invalid token: aud field is few or too much: {tokenStr}");
    }

    var tenant = retrieveTenantRowFromHeader(request);

    //     if err != nil {
    //     if errors.Is(err, sql.ErrNoRows) {
    //         return nil, echo.NewHTTPError(http.StatusUnauthorized, "tenant not found")

    //         }
    //     return nil, fmt.Errorf("error retrieveTenantRowFromHeader at parseViewer: %w", err)

    //     }
    if (tenant.name == "admin" && token.Role != RoleAdmin)
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, "tenant not found");
    }

    if (tenant.name != token.Aud[0])
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, $"invalid token: tenant name is not match with {request.Host}: {tokenStr}");
    }

    return new Viewer(token.Role, token.Sub, tenant.name, tenant.id);
}

TenantRow retrieveTenantRowFromHeader(HttpRequest request)
{
    // JWTに入っているテナント名とHostヘッダのテナント名が一致しているか確認
    var baseHost = getEnv("ISUCON_BASE_HOSTNAME", ".t.isucon.dev");
    var host = request.Host.ToString();
    var tenantName = Regex.Replace(host, baseHost + "$", "");

    app.Logger.LogInformation($"tenantName: {tenantName}");

    // SaaS管理者用ドメイン
    if (tenantName == "admin")
    {
        return new TenantRow(
            id: -1,
            name: "admin",
            display_name: "admin",
            created_at: -1,
            updated_at: -1
        );
    }

    // テナントの存在確認
    // XXX リクエストスコープ
    var adminDb = connectAdminDB();
    var tenant = adminDb.Query<TenantRow>("SELECT * FROM tenant WHERE name = @Name", new { Name = tenantName }).FirstOrDefault();

    if (tenant == null)
    {
        throw new IsuHttpException(HttpStatusCode.Unauthorized, $"tenant not found");
    }
    return tenant;
}

// // 参加者を取得する
// func retrievePlayer(ctx context.Context, tenantDB dbOrTx, id string) (*PlayerRow, error) {
// 	var p PlayerRow
// 	if err := tenantDB.GetContext(ctx, &p, "SELECT * FROM player WHERE id = ?", id); err != nil {
// 		return nil, fmt.Errorf("error Select player: id=%s, %w", id, err)
// 	}
// 	return &p, nil
// }

// // 参加者を認可する
// // 参加者向けAPIで呼ばれる
// func authorizePlayer(ctx context.Context, tenantDB dbOrTx, id string) error {
// 	player, err := retrievePlayer(ctx, tenantDB, id)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return echo.NewHTTPError(http.StatusUnauthorized, "player not found")
// 		}
// 		return fmt.Errorf("error retrievePlayer from viewer: %w", err)
// 	}
// 	if player.IsDisqualified {
// 		return echo.NewHTTPError(http.StatusForbidden, "player is disqualified")
// 	}
// 	return nil
// }


// 大会を取得する
CompetitionRow retrieveCompetition(SqliteConnection tenantDB, string id)
{
    return tenantDB.Query<CompetitionRow>("SELECT * FROM competition WHERE id = ?", new { id = id }).First();
}

// type PlayerScoreRow struct {
// 	TenantID      int64  `db:"tenant_id"`
// 	ID            string `db:"id"`
// 	PlayerID      string `db:"player_id"`
// 	CompetitionID string `db:"competition_id"`
// 	Score         int64  `db:"score"`
// 	RowNum        int64  `db:"row_num"`
// 	CreatedAt     int64  `db:"created_at"`
// 	UpdatedAt     int64  `db:"updated_at"`
// }

// // 排他ロックのためのファイル名を生成する
// func lockFilePath(id int64) string {
// 	tenantDBDir := getEnv("ISUCON_TENANT_DB_DIR", "../tenant_db")
// 	return filepath.Join(tenantDBDir, fmt.Sprintf("%d.lock", id))
// }

// // 排他ロックする
// func flockByTenantID(tenantID int64) (io.Closer, error) {
// 	p := lockFilePath(tenantID)

// 	fl := flock.New(p)
// 	if err := fl.Lock(); err != nil {
// 		return nil, fmt.Errorf("error flock.Lock: path=%s, %w", p, err)
// 	}
// 	return fl, nil
// }

// SasS管理者用API
// テナントを追加する
// POST /api/admin/tenants/add
async Task<SuccessResult<TenantsAddHandlerResult>> tenantsAddHandler(HttpRequest request)
{
    var v = await parseViewer(request);

    //     if err != nil {
    //     return fmt.Errorf("error parseViewer: %w", err)

    //     }
    if (v.tenantName != "admin")
    {
        // admin: SaaS管理者用の特別なテナント名
        throw new IsuHttpException(HttpStatusCode.NotFound, $"{v.tenantName} has not this API");
    }

    if (v.role != RoleAdmin)
    {
        throw new IsuHttpException(HttpStatusCode.Forbidden, $"admin role required");
    }
    var displayName = request.Form["display_name"].FirstOrDefault() ?? "";
    var name = request.Form["name"].FirstOrDefault() ?? "";

    validateTenantName(name);

    // ctx:= context.Background()

    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    // XXX リクエストスコープ
    var adminDb = connectAdminDB();
    using var insertCmd = new MySqlCommand(
        "INSERT INTO tenant (name, display_name, created_at, updated_at) VALUES (@name, @display_name, @created_at, @updated_at)", adminDb);
    insertCmd.Parameters.AddWithValue("name", name);
    insertCmd.Parameters.AddWithValue("display_name", displayName);
    insertCmd.Parameters.AddWithValue("created_at", now);
    insertCmd.Parameters.AddWithValue("updated_at", now);
    var insertRes = await insertCmd.ExecuteNonQueryAsync();
    app.Logger.LogInformation($"insertRes: {insertRes}");

    //     if err != nil {
    //     if merr, ok:= err.(*mysql.MySQLError); ok && merr.Number == 1062 { // duplicate entry
    //         return echo.NewHTTPError(http.StatusBadRequest, "duplicate tenant")

    //         }
    //     return fmt.Errorf(
    //         "error Insert tenant: name=%s, displayName=%s, createdAt=%d, updatedAt=%d, %w",
    //         name, displayName, now, now, err,

    //     )

    //     }

    var id = insertCmd.LastInsertedId;

    //     if err != nil {
    //     return fmt.Errorf("error get LastInsertId: %w", err)

    //     }
    // NOTE: 先にadminDBに書き込まれることでこのAPIの処理中に
    //       /api/admin/tenants/billingにアクセスされるとエラーになりそう
    //       ロックなどで対処したほうが良さそう
    await createTenantDB(id);
    // if err := createTenantDB(id); err != nil {
    //     return fmt.Errorf("error createTenantDB: id=%d name=%s %w", id, name, err)
    //     }

    var res = new SuccessResult<TenantsAddHandlerResult>(
        Status: true,
        Data: new TenantsAddHandlerResult(
            Tenant: new TenantWithBilling(
                ID: id.ToString(),
                Name: name,
                DisplayName: displayName,
                BillingYen: 0)));
    app.Logger.LogInformation(res.Data.Tenant.ToString());
    return res;
}

// テナント名が規則に沿っているかチェックする
void validateTenantName(string name)
{
    if (tenantNameRegexp.IsMatch(name))
    {
        return;
    }
    throw new IsuHttpException(HttpStatusCode.BadRequest, $"invalid tenant name: {name}");
}

// 大会ごとの課金レポートを計算する
BillingReport billingReportByCompetition(SqliteConnection tenantDB, Int64 tenantID, string competitonID)
{
    var comp = retrieveCompetition(tenantDB, competitonID);

    // ランキングにアクセスした参加者のIDを取得する
    using var adminDB = connectAdminDB();
    var vhs = adminDB.Query<VisitHistorySummaryRow>(
        "SELECT player_id, MIN(created_at) AS min_created_at FROM visit_history WHERE tenant_id = @TenantId AND competition_id = @CompetitionId GROUP BY player_id",
        new { TenantId = tenantID, CompetitionId = comp.id }).ToList();

    //    ); err != nil && err != sql.ErrNoRows {
    //        return nil, fmt.Errorf("error Select visit_history: tenantID=%d, competitionID=%s, %w", tenantID, comp.ID, err)

    //     }
    var billingMap = new Dictionary<string, string>();
    foreach (var vh in vhs)
    {
        // competition.finished_atよりもあとの場合は、終了後に訪問したとみなして大会開催内アクセス済みとみなさない
        if (comp.finished_at.HasValue && comp.finished_at < vh.min_created_at)
        {
            continue;
        }
        billingMap[vh.player_id] = "visitor";
    }

    //    // player_scoreを読んでいるときに更新が走ると不整合が起こるのでロックを取得する
    //    fl, err:= flockByTenantID(tenantID)

    //     if err != nil {
    //        return nil, fmt.Errorf("error flockByTenantID: %w", err)

    //     }
    //    defer fl.Close()

    // スコアを登録した参加者のIDを取得する
    var scoredPlayerIDs = tenantDB.Query<dynamic>(
            "SELECT DISTINCT(player_id) FROM player_score WHERE tenant_id = @TenantId AND competition_id = @CompetitionId",
            new { TenantId = tenantID, CompetitionId = comp.id }).Select(x => $"{x.player_score}").ToList();


    //); err != nil && err != sql.ErrNoRows {
    //return nil, fmt.Errorf("error Select count player_score: tenantID=%d, competitionID=%s, %w", tenantID, competitonID, err)

    foreach (var pid in scoredPlayerIDs)
    {
        // スコアが登録されている参加者
        billingMap[pid] = "player";
    }

    // 大会が終了している場合のみ請求金額が確定するので計算する
    //var playerCount, visitorCount int64
    Int64 playerCount = 0;
    Int64 visitorCount = 0;
    if (comp.finished_at.HasValue)
    {
        foreach (var category in billingMap.Values)
        {
            switch (category)
            {
                case "player":
                    playerCount++; break;
                case "visitor":
                    visitorCount++; break;
            }
        }
    }
    return new BillingReport(
        CompetitionID: comp.id,
        CompetitionTitle: comp.title,
        PlayerCount: playerCount,
        VisitorCount: visitorCount,
        BillingPlayerYen: 100 * playerCount, // スコアを登録した参加者は100円
        BillingVisitorYen: 10 * visitorCount, // ランキングを閲覧だけした(スコアを登録していない)参加者は10円
        BillingYen: 100 * playerCount + 10 * visitorCount
    );
}


// SaaS管理者用API
// テナントごとの課金レポートを最大10件、テナントのid降順で取得する
// GET /api/admin/tenants/billing
// URL引数beforeを指定した場合、指定した値よりもidが小さいテナントの課金レポートを取得する
async Task<SuccessResult<TenantsBillingHandlerResult>> tenantsBillingHandler(HttpRequest request)
{
    var host = request.Host.ToString();
    if (host != getEnv("isucon_admin_hostname", "admin.t.isucon.dev"))
    {
        throw new IsuHttpException(HttpStatusCode.NotFound, $"invalid hostname {host}");
    }

    var v = await parseViewer(request);
    if (v.role != RoleAdmin)
    {
        throw new IsuHttpException(HttpStatusCode.Forbidden, $"admin role required");
    }
    var before = request.Query["before"].FirstOrDefault() ?? "";
    Int64 beforeID;
    if (!Int64.TryParse(before, out beforeID))
    {
        throw new IsuHttpException(HttpStatusCode.BadRequest, $"failed to parse query parameter 'before': {before}");
    }

    // テナントごとに
    //   大会ごとに
    //     scoreが登録されているplayer * 100
    //     scoreが登録されていないplayerでアクセスした人 * 10
    //   を合計したものを
    // テナントの課金とする
    var tenantBillings = new List<TenantWithBilling>();
    using var adminDB = connectAdminDB();
    var ts = adminDB.Query<TenantRow>("SELECT * FROM tenant ORDER BY id DESC").ToList();
    foreach (var t in ts)
    {
        if (beforeID != 0 && beforeID <= t.id) { continue; }
        var byen = 0L;
        using var tenantDB = connectToTenantDB(t.id);
        var cs = tenantDB.Query<CompetitionRow>("SELECT * FROM competition WHERE tenant_id=@Id", new { Id = t.id }).ToList();
        foreach (var comp in cs)
        {
            var report = billingReportByCompetition(tenantDB, t.id, comp.id);
            byen += report.BillingYen;
        }

        tenantBillings.Add(new TenantWithBilling(ID: t.id.ToString(), Name: t.name, DisplayName: t.display_name, BillingYen: byen));
        if (tenantBillings.Count > 10) { break; }
    }

    return new SuccessResult<TenantsBillingHandlerResult>(
        Status: true,
        Data: new TenantsBillingHandlerResult(
            Tenants: tenantBillings));
}


// // テナント管理者向けAPI
// // GET /api/organizer/players
// // 参加者一覧を返す
// func playersListHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return err
// 	} else if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return fmt.Errorf("error connectToTenantDB: %w", err)
// 	}
// 	defer tenantDB.Close()

// 	var pls []PlayerRow
// 	if err := tenantDB.SelectContext(
// 		ctx,
// 		&pls,
// 		"SELECT * FROM player WHERE tenant_id=? ORDER BY created_at DESC",
// 		v.tenantID,
// 	); err != nil {
// 		return fmt.Errorf("error Select player: %w", err)
// 	}
// 	var pds []PlayerDetail
// 	for _, p := range pls {
// 		pds = append(pds, PlayerDetail{
// 			ID:             p.ID,
// 			DisplayName:    p.DisplayName,
// 			IsDisqualified: p.IsDisqualified,
// 		})
// 	}

// 	res := PlayersListHandlerResult{
// 		Players: pds,
// 	}
// 	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
// }

// type PlayersAddHandlerResult struct {
// 	Players []PlayerDetail `json:"players"`
// }

// // テナント管理者向けAPI
// // GET /api/organizer/players/add
// // テナントに参加者を追加する
// func playersAddHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	} else if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	params, err := c.FormParams()
// 	if err != nil {
// 		return fmt.Errorf("error c.FormParams: %w", err)
// 	}
// 	displayNames := params["display_name[]"]

// 	pds := make([]PlayerDetail, 0, len(displayNames))
// 	for _, displayName := range displayNames {
// 		id, err := dispenseID(ctx)
// 		if err != nil {
// 			return fmt.Errorf("error dispenseID: %w", err)
// 		}

// 		now := time.Now().Unix()
// 		if _, err := tenantDB.ExecContext(
// 			ctx,
// 			"INSERT INTO player (id, tenant_id, display_name, is_disqualified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
// 			id, v.tenantID, displayName, false, now, now,
// 		); err != nil {
// 			return fmt.Errorf(
// 				"error Insert player at tenantDB: id=%s, displayName=%s, isDisqualified=%t, createdAt=%d, updatedAt=%d, %w",
// 				id, displayName, false, now, now, err,
// 			)
// 		}
// 		p, err := retrievePlayer(ctx, tenantDB, id)
// 		if err != nil {
// 			return fmt.Errorf("error retrievePlayer: %w", err)
// 		}
// 		pds = append(pds, PlayerDetail{
// 			ID:             p.ID,
// 			DisplayName:    p.DisplayName,
// 			IsDisqualified: p.IsDisqualified,
// 		})
// 	}

// 	res := PlayersAddHandlerResult{
// 		Players: pds,
// 	}
// 	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
// }

// type PlayerDisqualifiedHandlerResult struct {
// 	Player PlayerDetail `json:"player"`
// }

// // テナント管理者向けAPI
// // POST /api/organizer/player/:player_id/disqualified
// // 参加者を失格にする
// func playerDisqualifiedHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	} else if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	playerID := c.Param("player_id")

// 	now := time.Now().Unix()
// 	if _, err := tenantDB.ExecContext(
// 		ctx,
// 		"UPDATE player SET is_disqualified = ?, updated_at = ? WHERE id = ?",
// 		true, now, playerID,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"error Update player: isDisqualified=%t, updatedAt=%d, id=%s, %w",
// 			true, now, playerID, err,
// 		)
// 	}
// 	p, err := retrievePlayer(ctx, tenantDB, playerID)
// 	if err != nil {
// 		// 存在しないプレイヤー
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return echo.NewHTTPError(http.StatusNotFound, "player not found")
// 		}
// 		return fmt.Errorf("error retrievePlayer: %w", err)
// 	}

// 	res := PlayerDisqualifiedHandlerResult{
// 		Player: PlayerDetail{
// 			ID:             p.ID,
// 			DisplayName:    p.DisplayName,
// 			IsDisqualified: p.IsDisqualified,
// 		},
// 	}
// 	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
// }

// type CompetitionDetail struct {
// 	ID         string `json:"id"`
// 	Title      string `json:"title"`
// 	IsFinished bool   `json:"is_finished"`
// }

// type CompetitionsAddHandlerResult struct {
// 	Competition CompetitionDetail `json:"competition"`
// }

// // テナント管理者向けAPI
// // POST /api/organizer/competitions/add
// // 大会を追加する
// func competitionsAddHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	} else if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	title := c.FormValue("title")

// 	now := time.Now().Unix()
// 	id, err := dispenseID(ctx)
// 	if err != nil {
// 		return fmt.Errorf("error dispenseID: %w", err)
// 	}
// 	if _, err := tenantDB.ExecContext(
// 		ctx,
// 		"INSERT INTO competition (id, tenant_id, title, finished_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
// 		id, v.tenantID, title, sql.NullInt64{}, now, now,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"error Insert competition: id=%s, tenant_id=%d, title=%s, finishedAt=null, createdAt=%d, updatedAt=%d, %w",
// 			id, v.tenantID, title, now, now, err,
// 		)
// 	}

// 	res := CompetitionsAddHandlerResult{
// 		Competition: CompetitionDetail{
// 			ID:         id,
// 			Title:      title,
// 			IsFinished: false,
// 		},
// 	}
// 	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
// }

// // テナント管理者向けAPI
// // POST /api/organizer/competition/:competition_id/finish
// // 大会を終了する
// func competitionFinishHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	} else if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	id := c.Param("competition_id")
// 	if id == "" {
// 		return echo.NewHTTPError(http.StatusBadRequest, "competition_id required")
// 	}
// 	_, err = retrieveCompetition(ctx, tenantDB, id)
// 	if err != nil {
// 		// 存在しない大会
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return echo.NewHTTPError(http.StatusNotFound, "competition not found")
// 		}
// 		return fmt.Errorf("error retrieveCompetition: %w", err)
// 	}

// 	now := time.Now().Unix()
// 	if _, err := tenantDB.ExecContext(
// 		ctx,
// 		"UPDATE competition SET finished_at = ?, updated_at = ? WHERE id = ?",
// 		now, now, id,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"error Update competition: finishedAt=%d, updatedAt=%d, id=%s, %w",
// 			now, now, id, err,
// 		)
// 	}
// 	return c.JSON(http.StatusOK, SuccessResult{Status: true})
// }

// type ScoreHandlerResult struct {
// 	Rows int64 `json:"rows"`
// }

// // テナント管理者向けAPI
// // POST /api/organizer/competition/:competition_id/score
// // 大会のスコアをCSVでアップロードする
// func competitionScoreHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	}
// 	if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	competitionID := c.Param("competition_id")
// 	if competitionID == "" {
// 		return echo.NewHTTPError(http.StatusBadRequest, "competition_id required")
// 	}
// 	comp, err := retrieveCompetition(ctx, tenantDB, competitionID)
// 	if err != nil {
// 		// 存在しない大会
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return echo.NewHTTPError(http.StatusNotFound, "competition not found")
// 		}
// 		return fmt.Errorf("error retrieveCompetition: %w", err)
// 	}
// 	if comp.FinishedAt.Valid {
// 		res := FailureResult{
// 			Status:  false,
// 			Message: "competition is finished",
// 		}
// 		return c.JSON(http.StatusBadRequest, res)
// 	}

// 	fh, err := c.FormFile("scores")
// 	if err != nil {
// 		return fmt.Errorf("error c.FormFile(scores): %w", err)
// 	}
// 	f, err := fh.Open()
// 	if err != nil {
// 		return fmt.Errorf("error fh.Open FormFile(scores): %w", err)
// 	}
// 	defer f.Close()

// 	r := csv.NewReader(f)
// 	headers, err := r.Read()
// 	if err != nil {
// 		return fmt.Errorf("error r.Read at header: %w", err)
// 	}
// 	if !reflect.DeepEqual(headers, []string{"player_id", "score"}) {
// 		return echo.NewHTTPError(http.StatusBadRequest, "invalid CSV headers")
// 	}

// 	// / DELETEしたタイミングで参照が来ると空っぽのランキングになるのでロックする
// 	fl, err := flockByTenantID(v.tenantID)
// 	if err != nil {
// 		return fmt.Errorf("error flockByTenantID: %w", err)
// 	}
// 	defer fl.Close()
// 	var rowNum int64
// 	playerScoreRows := []PlayerScoreRow{}
// 	for {
// 		rowNum++
// 		row, err := r.Read()
// 		if err != nil {
// 			if err == io.EOF {
// 				break
// 			}
// 			return fmt.Errorf("error r.Read at rows: %w", err)
// 		}
// 		if len(row) != 2 {
// 			return fmt.Errorf("row must have two columns: %#v", row)
// 		}
// 		playerID, scoreStr := row[0], row[1]
// 		if _, err := retrievePlayer(ctx, tenantDB, playerID); err != nil {
// 			// 存在しない参加者が含まれている
// 			if errors.Is(err, sql.ErrNoRows) {
// 				return echo.NewHTTPError(
// 					http.StatusBadRequest,
// 					fmt.Sprintf("player not found: %s", playerID),
// 				)
// 			}
// 			return fmt.Errorf("error retrievePlayer: %w", err)
// 		}
// 		var score int64
// 		if score, err = strconv.ParseInt(scoreStr, 10, 64); err != nil {
// 			return echo.NewHTTPError(
// 				http.StatusBadRequest,
// 				fmt.Sprintf("error strconv.ParseUint: scoreStr=%s, %s", scoreStr, err),
// 			)
// 		}
// 		id, err := dispenseID(ctx)
// 		if err != nil {
// 			return fmt.Errorf("error dispenseID: %w", err)
// 		}
// 		now := time.Now().Unix()
// 		playerScoreRows = append(playerScoreRows, PlayerScoreRow{
// 			ID:            id,
// 			TenantID:      v.tenantID,
// 			PlayerID:      playerID,
// 			CompetitionID: competitionID,
// 			Score:         score,
// 			RowNum:        rowNum,
// 			CreatedAt:     now,
// 			UpdatedAt:     now,
// 		})
// 	}

// 	if _, err := tenantDB.ExecContext(
// 		ctx,
// 		"DELETE FROM player_score WHERE tenant_id = ? AND competition_id = ?",
// 		v.tenantID,
// 		competitionID,
// 	); err != nil {
// 		return fmt.Errorf("error Delete player_score: tenantID=%d, competitionID=%s, %w", v.tenantID, competitionID, err)
// 	}
// 	for _, ps := range playerScoreRows {
// 		if _, err := tenantDB.NamedExecContext(
// 			ctx,
// 			"INSERT INTO player_score (id, tenant_id, player_id, competition_id, score, row_num, created_at, updated_at) VALUES (:id, :tenant_id, :player_id, :competition_id, :score, :row_num, :created_at, :updated_at)",
// 			ps,
// 		); err != nil {
// 			return fmt.Errorf(
// 				"error Insert player_score: id=%s, tenant_id=%d, playerID=%s, competitionID=%s, score=%d, rowNum=%d, createdAt=%d, updatedAt=%d, %w",
// 				ps.ID, ps.TenantID, ps.PlayerID, ps.CompetitionID, ps.Score, ps.RowNum, ps.CreatedAt, ps.UpdatedAt, err,
// 			)

// 		}
// 	}

// 	return c.JSON(http.StatusOK, SuccessResult{
// 		Status: true,
// 		Data:   ScoreHandlerResult{Rows: int64(len(playerScoreRows))},
// 	})
// }

// type BillingHandlerResult struct {
// 	Reports []BillingReport `json:"reports"`
// }

// // テナント管理者向けAPI
// // GET /api/organizer/billing
// // テナント内の課金レポートを取得する
// func billingHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	}
// 	if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	cs := []CompetitionRow{}
// 	if err := tenantDB.SelectContext(
// 		ctx,
// 		&cs,
// 		"SELECT * FROM competition WHERE tenant_id=? ORDER BY created_at DESC",
// 		v.tenantID,
// 	); err != nil {
// 		return fmt.Errorf("error Select competition: %w", err)
// 	}
// 	tbrs := make([]BillingReport, 0, len(cs))
// 	for _, comp := range cs {
// 		report, err := billingReportByCompetition(ctx, tenantDB, v.tenantID, comp.ID)
// 		if err != nil {
// 			return fmt.Errorf("error billingReportByCompetition: %w", err)
// 		}
// 		tbrs = append(tbrs, *report)
// 	}

// 	res := SuccessResult{
// 		Status: true,
// 		Data: BillingHandlerResult{
// 			Reports: tbrs,
// 		},
// 	}
// 	return c.JSON(http.StatusOK, res)
// }

// type PlayerScoreDetail struct {
// 	CompetitionTitle string `json:"competition_title"`
// 	Score            int64  `json:"score"`
// }

// type PlayerHandlerResult struct {
// 	Player PlayerDetail        `json:"player"`
// 	Scores []PlayerScoreDetail `json:"scores"`
// }

// // 参加者向けAPI
// // GET /api/player/player/:player_id
// // 参加者の詳細情報を取得する
// func playerHandler(c echo.Context) error {
// 	ctx := context.Background()

// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return err
// 	}
// 	if v.role != RolePlayer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role player required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	if err := authorizePlayer(ctx, tenantDB, v.playerID); err != nil {
// 		return err
// 	}

// 	playerID := c.Param("player_id")
// 	if playerID == "" {
// 		return echo.NewHTTPError(http.StatusBadRequest, "player_id is required")
// 	}
// 	p, err := retrievePlayer(ctx, tenantDB, playerID)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return echo.NewHTTPError(http.StatusNotFound, "player not found")
// 		}
// 		return fmt.Errorf("error retrievePlayer: %w", err)
// 	}
// 	cs := []CompetitionRow{}
// 	if err := tenantDB.SelectContext(
// 		ctx,
// 		&cs,
// 		"SELECT * FROM competition WHERE tenant_id = ? ORDER BY created_at ASC",
// 		v.tenantID,
// 	); err != nil && !errors.Is(err, sql.ErrNoRows) {
// 		return fmt.Errorf("error Select competition: %w", err)
// 	}

// 	// player_scoreを読んでいるときに更新が走ると不整合が起こるのでロックを取得する
// 	fl, err := flockByTenantID(v.tenantID)
// 	if err != nil {
// 		return fmt.Errorf("error flockByTenantID: %w", err)
// 	}
// 	defer fl.Close()
// 	pss := make([]PlayerScoreRow, 0, len(cs))
// 	for _, c := range cs {
// 		ps := PlayerScoreRow{}
// 		if err := tenantDB.GetContext(
// 			ctx,
// 			&ps,
// 			// 最後にCSVに登場したスコアを採用する = row_numが一番大きいもの
// 			"SELECT * FROM player_score WHERE tenant_id = ? AND competition_id = ? AND player_id = ? ORDER BY row_num DESC LIMIT 1",
// 			v.tenantID,
// 			c.ID,
// 			p.ID,
// 		); err != nil {
// 			// 行がない = スコアが記録されてない
// 			if errors.Is(err, sql.ErrNoRows) {
// 				continue
// 			}
// 			return fmt.Errorf("error Select player_score: tenantID=%d, competitionID=%s, playerID=%s, %w", v.tenantID, c.ID, p.ID, err)
// 		}
// 		pss = append(pss, ps)
// 	}

// 	psds := make([]PlayerScoreDetail, 0, len(pss))
// 	for _, ps := range pss {
// 		comp, err := retrieveCompetition(ctx, tenantDB, ps.CompetitionID)
// 		if err != nil {
// 			return fmt.Errorf("error retrieveCompetition: %w", err)
// 		}
// 		psds = append(psds, PlayerScoreDetail{
// 			CompetitionTitle: comp.Title,
// 			Score:            ps.Score,
// 		})
// 	}

// 	res := SuccessResult{
// 		Status: true,
// 		Data: PlayerHandlerResult{
// 			Player: PlayerDetail{
// 				ID:             p.ID,
// 				DisplayName:    p.DisplayName,
// 				IsDisqualified: p.IsDisqualified,
// 			},
// 			Scores: psds,
// 		},
// 	}
// 	return c.JSON(http.StatusOK, res)
// }

// type CompetitionRank struct {
// 	Rank              int64  `json:"rank"`
// 	Score             int64  `json:"score"`
// 	PlayerID          string `json:"player_id"`
// 	PlayerDisplayName string `json:"player_display_name"`
// 	RowNum            int64  `json:"-"` // APIレスポンスのJSONには含まれない
// }

// type CompetitionRankingHandlerResult struct {
// 	Competition CompetitionDetail `json:"competition"`
// 	Ranks       []CompetitionRank `json:"ranks"`
// }

// // 参加者向けAPI
// // GET /api/player/competition/:competition_id/ranking
// // 大会ごとのランキングを取得する
// func competitionRankingHandler(c echo.Context) error {
// 	ctx := context.Background()
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return err
// 	}
// 	if v.role != RolePlayer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role player required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	if err := authorizePlayer(ctx, tenantDB, v.playerID); err != nil {
// 		return err
// 	}

// 	competitionID := c.Param("competition_id")
// 	if competitionID == "" {
// 		return echo.NewHTTPError(http.StatusBadRequest, "competition_id is required")
// 	}

// 	// 大会の存在確認
// 	competition, err := retrieveCompetition(ctx, tenantDB, competitionID)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return echo.NewHTTPError(http.StatusNotFound, "competition not found")
// 		}
// 		return fmt.Errorf("error retrieveCompetition: %w", err)
// 	}

// 	now := time.Now().Unix()
// 	var tenant TenantRow
// 	if err := adminDB.GetContext(ctx, &tenant, "SELECT * FROM tenant WHERE id = ?", v.tenantID); err != nil {
// 		return fmt.Errorf("error Select tenant: id=%d, %w", v.tenantID, err)
// 	}

// 	if _, err := adminDB.ExecContext(
// 		ctx,
// 		"INSERT INTO visit_history (player_id, tenant_id, competition_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
// 		v.playerID, tenant.ID, competitionID, now, now,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"error Insert visit_history: playerID=%s, tenantID=%d, competitionID=%s, createdAt=%d, updatedAt=%d, %w",
// 			v.playerID, tenant.ID, competitionID, now, now, err,
// 		)
// 	}

// 	var rankAfter int64
// 	rankAfterStr := c.QueryParam("rank_after")
// 	if rankAfterStr != "" {
// 		if rankAfter, err = strconv.ParseInt(rankAfterStr, 10, 64); err != nil {
// 			return fmt.Errorf("error strconv.ParseUint: rankAfterStr=%s, %w", rankAfterStr, err)
// 		}
// 	}

// 	// player_scoreを読んでいるときに更新が走ると不整合が起こるのでロックを取得する
// 	fl, err := flockByTenantID(v.tenantID)
// 	if err != nil {
// 		return fmt.Errorf("error flockByTenantID: %w", err)
// 	}
// 	defer fl.Close()
// 	pss := []PlayerScoreRow{}
// 	if err := tenantDB.SelectContext(
// 		ctx,
// 		&pss,
// 		"SELECT * FROM player_score WHERE tenant_id = ? AND competition_id = ? ORDER BY row_num DESC",
// 		tenant.ID,
// 		competitionID,
// 	); err != nil {
// 		return fmt.Errorf("error Select player_score: tenantID=%d, competitionID=%s, %w", tenant.ID, competitionID, err)
// 	}
// 	ranks := make([]CompetitionRank, 0, len(pss))
// 	scoredPlayerSet := make(map[string]struct{}, len(pss))
// 	for _, ps := range pss {
// 		// player_scoreが同一player_id内ではrow_numの降順でソートされているので
// 		// 現れたのが2回目以降のplayer_idはより大きいrow_numでスコアが出ているとみなせる
// 		if _, ok := scoredPlayerSet[ps.PlayerID]; ok {
// 			continue
// 		}
// 		scoredPlayerSet[ps.PlayerID] = struct{}{}
// 		p, err := retrievePlayer(ctx, tenantDB, ps.PlayerID)
// 		if err != nil {
// 			return fmt.Errorf("error retrievePlayer: %w", err)
// 		}
// 		ranks = append(ranks, CompetitionRank{
// 			Score:             ps.Score,
// 			PlayerID:          p.ID,
// 			PlayerDisplayName: p.DisplayName,
// 			RowNum:            ps.RowNum,
// 		})
// 	}
// 	sort.Slice(ranks, func(i, j int) bool {
// 		if ranks[i].Score == ranks[j].Score {
// 			return ranks[i].RowNum < ranks[j].RowNum
// 		}
// 		return ranks[i].Score > ranks[j].Score
// 	})
// 	pagedRanks := make([]CompetitionRank, 0, 100)
// 	for i, rank := range ranks {
// 		if int64(i) < rankAfter {
// 			continue
// 		}
// 		pagedRanks = append(pagedRanks, CompetitionRank{
// 			Rank:              int64(i + 1),
// 			Score:             rank.Score,
// 			PlayerID:          rank.PlayerID,
// 			PlayerDisplayName: rank.PlayerDisplayName,
// 		})
// 		if len(pagedRanks) >= 100 {
// 			break
// 		}
// 	}

// 	res := SuccessResult{
// 		Status: true,
// 		Data: CompetitionRankingHandlerResult{
// 			Competition: CompetitionDetail{
// 				ID:         competition.ID,
// 				Title:      competition.Title,
// 				IsFinished: competition.FinishedAt.Valid,
// 			},
// 			Ranks: pagedRanks,
// 		},
// 	}
// 	return c.JSON(http.StatusOK, res)
// }

// type CompetitionsHandlerResult struct {
// 	Competitions []CompetitionDetail `json:"competitions"`
// }

// // 参加者向けAPI
// // GET /api/player/competitions
// // 大会の一覧を取得する
// func playerCompetitionsHandler(c echo.Context) error {
// 	ctx := context.Background()

// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return err
// 	}
// 	if v.role != RolePlayer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role player required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	if err := authorizePlayer(ctx, tenantDB, v.playerID); err != nil {
// 		return err
// 	}
// 	return competitionsHandler(c, v, tenantDB)
// }

// // テナント管理者向けAPI
// // GET /api/organizer/competitions
// // 大会の一覧を取得する
// func organizerCompetitionsHandler(c echo.Context) error {
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		return err
// 	}
// 	if v.role != RoleOrganizer {
// 		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return err
// 	}
// 	defer tenantDB.Close()

// 	return competitionsHandler(c, v, tenantDB)
// }

// func competitionsHandler(c echo.Context, v *Viewer, tenantDB dbOrTx) error {
// 	ctx := context.Background()

// 	cs := []CompetitionRow{}
// 	if err := tenantDB.SelectContext(
// 		ctx,
// 		&cs,
// 		"SELECT * FROM competition WHERE tenant_id=? ORDER BY created_at DESC",
// 		v.tenantID,
// 	); err != nil {
// 		return fmt.Errorf("error Select competition: %w", err)
// 	}
// 	cds := make([]CompetitionDetail, 0, len(cs))
// 	for _, comp := range cs {
// 		cds = append(cds, CompetitionDetail{
// 			ID:         comp.ID,
// 			Title:      comp.Title,
// 			IsFinished: comp.FinishedAt.Valid,
// 		})
// 	}

// 	res := SuccessResult{
// 		Status: true,
// 		Data: CompetitionsHandlerResult{
// 			Competitions: cds,
// 		},
// 	}
// 	return c.JSON(http.StatusOK, res)
// }

// // 共通API
// // GET /api/me
// // JWTで認証した結果、テナントやユーザ情報を返す
// func meHandler(c echo.Context) error {
// 	tenant, err := retrieveTenantRowFromHeader(c)
// 	if err != nil {
// 		return fmt.Errorf("error retrieveTenantRowFromHeader: %w", err)
// 	}
// 	td := &TenantDetail{
// 		Name:        tenant.Name,
// 		DisplayName: tenant.DisplayName,
// 	}
// 	v, err := parseViewer(c)
// 	if err != nil {
// 		var he *echo.HTTPError
// 		if ok := errors.As(err, &he); ok && he.Code == http.StatusUnauthorized {
// 			return c.JSON(http.StatusOK, SuccessResult{
// 				Status: true,
// 				Data: MeHandlerResult{
// 					Tenant:   td,
// 					Me:       nil,
// 					Role:     RoleNone,
// 					LoggedIn: false,
// 				},
// 			})
// 		}
// 		return fmt.Errorf("error parseViewer: %w", err)
// 	}
// 	if v.role == RoleAdmin || v.role == RoleOrganizer {
// 		return c.JSON(http.StatusOK, SuccessResult{
// 			Status: true,
// 			Data: MeHandlerResult{
// 				Tenant:   td,
// 				Me:       nil,
// 				Role:     v.role,
// 				LoggedIn: true,
// 			},
// 		})
// 	}

// 	tenantDB, err := connectToTenantDB(v.tenantID)
// 	if err != nil {
// 		return fmt.Errorf("error connectToTenantDB: %w", err)
// 	}
// 	ctx := context.Background()
// 	p, err := retrievePlayer(ctx, tenantDB, v.playerID)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return c.JSON(http.StatusOK, SuccessResult{
// 				Status: true,
// 				Data: MeHandlerResult{
// 					Tenant:   td,
// 					Me:       nil,
// 					Role:     RoleNone,
// 					LoggedIn: false,
// 				},
// 			})
// 		}
// 		return fmt.Errorf("error retrievePlayer: %w", err)
// 	}

// 	return c.JSON(http.StatusOK, SuccessResult{
// 		Status: true,
// 		Data: MeHandlerResult{
// 			Tenant: td,
// 			Me: &PlayerDetail{
// 				ID:             p.ID,
// 				DisplayName:    p.DisplayName,
// 				IsDisqualified: p.IsDisqualified,
// 			},
// 			Role:     v.role,
// 			LoggedIn: true,
// 		},
// 	})
// }

// ベンチマーカー向けAPI
// POST /initialize
// ベンチマーカーが起動したときに最初に呼ぶ
// データベースの初期化などが実行されるため、スキーマを変更した場合などは適宜改変すること
async Task<SuccessResult<InitializeHandlerResult>> initializeHandler()
{
    var p = Process.Start(Path.GetFullPath(initializeScript));
    await p.WaitForExitAsync();
    if (p.ExitCode != 0)
    {
        var output = await p.StandardOutput.ReadToEndAsync() + await p.StandardError.ReadToEndAsync();
        throw new Exception($"error {initializeScript}: {p.ExitCode} {output}");
    }
    return new SuccessResult<InitializeHandlerResult>(true, new InitializeHandlerResult(
        Lang: "csharp"
    ));
}

class IsuHttpException : Exception
{
    private int Status;
    public IsuHttpException(HttpStatusCode status, string message) : base(message)
    {
        Status = (int)status;
    }
}

// {"aud":["admin"],"exp":1659978506,"iss":"isuports","role":"admin","sub":"admin"}
record Token(string[] Aud, Int64 Exp, string Iss, string Role, string Sub) { }

record TenantRow(Int64 id, string name, string display_name, Int64 created_at, Int64 updated_at) { }

record CompetitionRow(string id, Int64 tenant_id, string title, Int64? finished_at, Int64 created_at, Int64 updated_at) { }

// type dbOrTx interface {
// 	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
// 	SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
// 	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
// }

// type PlayerRow struct {
// 	TenantID       int64  `db:"tenant_id"`
// 	ID             string `db:"id"`
// 	DisplayName    string `db:"display_name"`
// 	IsDisqualified bool   `db:"is_disqualified"`
// 	CreatedAt      int64  `db:"created_at"`
// 	UpdatedAt      int64  `db:"updated_at"`
// }

record BillingReport(
    [property: JsonPropertyName("competition_id")] string CompetitionID,
    [property: JsonPropertyName("competition_title")] string CompetitionTitle,
    // スコアを登録した参加者数
    [property: JsonPropertyName("player_count")] Int64 PlayerCount,
    // ランキングを閲覧だけした(スコアを登録していない)参加者数
    [property: JsonPropertyName("visitor_count")] Int64 VisitorCount,
    // 請求金額 スコアを登録した参加者分
    [property: JsonPropertyName("billing_player_yen")] Int64 BillingPlayerYen,
    // 請求金額 ランキングを閲覧だけした(スコアを登録していない)参加者分
    [property: JsonPropertyName("billing_visitor_yen")] Int64 BillingVisitorYen,
    // 合計請求金額
    [property: JsonPropertyName("billing_yen")] Int64 BillingYen)
{ }

record VisitHistoryRow(string player_id, Int64 tenant_id, string competition_id, Int64 created_at, Int64 updated_at) { }

record VisitHistorySummaryRow(
    [property: JsonPropertyName("player_id")] string player_id,
    [property: JsonPropertyName("min_created_at")] Int64 min_created_at)
{ }

// アクセスしてきた人の情報
record Viewer(string role, string playerID, string tenantName, Int64 tenantID) { }

record TenantDetail(string Name, string DisplayName) { }

record TenantWithBilling(
    string ID,
    string Name,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("billing")] Int64 BillingYen)
{ }

record PlayerDetail(string ID, string DisplayName, bool IsDisqualified) { }

record SuccessResult<T>(bool Status, T Data) { };
record FailureResult(bool Status, string Message) { };

record MeHandlerResult(TenantDetail Tenant, PlayerDetail Me, string Role, bool LoggedIn) { }
record TenantsBillingHandlerResult(IList<TenantWithBilling> Tenants) { }
record PlayersListHandlerResult(IList<PlayerDetail> Players) { }

record TenantsAddHandlerResult(TenantWithBilling Tenant) { }

record InitializeHandlerResult(string Lang) { };

public class CachePrivateAttribute : Attribute { }
