package vendors

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// pgVectorTypes 是 pgvector 扩展的列类型名集合。
var pgVectorTypes = map[string]struct{}{
	"vector":    {},
	"halfvec":   {},
	"sparsevec": {},
	"bit":       {},
}

// PgVector 实现 PostgreSQL pgvector 扩展的只读适配器。
type PgVector struct {
	Base
}

// NewPgVector 创建 pgvector 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewPgVector(runtime *engine.Runtime) *PgVector {
	return &PgVector{Base: Base{VendorID: model.VendorPgVector, Ports: []int{5432}, Runtime: runtime}}
}

// Fingerprint 识别 PostgreSQL 与 pgvector 扩展。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；无法建立会话时返回 engine.ErrNotMatched。
func (p *PgVector) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	conn, err := p.connect(ctx, target, options)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "authentication") || strings.Contains(lower, "password") || strings.Contains(lower, "role") {
			return &model.Fingerprint{
				Vendor:       model.VendorPgVector,
				Product:      "postgresql",
				Confidence:   model.ConfidenceHigh,
				AuthRequired: true,
				TLS:          target.TLS,
				Evidence:     []string{"server rejected authentication: " + utilities.Truncate(err.Error(), 160)},
			}, nil
		}
		return nil, engine.ErrNotMatched
	}
	defer func() { _ = conn.Close(ctx) }()
	version := p.scalar(ctx, conn, "SHOW server_version")
	if version == "" {
		return nil, engine.ErrNotMatched
	}
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorPgVector,
		Product:    "postgresql",
		Version:    version,
		Confidence: model.ConfidenceHigh,
		TLS:        target.TLS,
		Evidence:   []string{"server_version=" + version},
	}
	extension := p.scalar(ctx, conn, "SELECT extversion FROM pg_extension WHERE extname = 'vector'")
	if extension != "" {
		fingerprint.Product = "postgresql+pgvector"
		fingerprint.Evidence = append(fingerprint.Evidence, "pgvector extversion="+extension)
	} else {
		fingerprint.Metadata = map[string]any{"pgvector_extension": false}
	}
	if user := p.scalar(ctx, conn, "SELECT current_user"); user != "" {
		fingerprint.Evidence = append(fingerprint.Evidence, "current_user="+user)
	}
	return fingerprint, nil
}

// Enumerate 枚举含向量列的表并只读提取行样本。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制记录上限与向量采样。返回集合、记录与统计。
func (p *PgVector) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorPgVector, TargetID: target.ID}
	conn, err := p.connect(ctx, target, options)
	if err != nil {
		return extraction, err
	}
	defer func() { _ = conn.Close(ctx) }()
	groups, err := p.vectorTables(ctx, conn)
	if err != nil {
		return extraction, err
	}
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.qualified)
	}
	sort.Strings(names)
	for _, qualified := range names {
		group := groups[qualified]
		if dump.Collection != "" && group.table != dump.Collection {
			continue
		}
		collection := p.describe(ctx, conn, target, group)
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, queryErr := p.rows(ctx, conn, target, collection, group, dump)
		if queryErr != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", qualified, queryErr))
			continue
		}
		extraction.Records = append(extraction.Records, records...)
		if len(extraction.Records) >= dump.MaxRecords {
			extraction.Stats.Limited = true
			break
		}
	}
	return extraction, nil
}

type vectorTable struct {
	schema    string
	table     string
	qualified string
	columns   []vectorColumn
}

type vectorColumn struct {
	name     string
	dataType string
	vector   bool
}

func (p *PgVector) connect(ctx context.Context, target *model.Target, options model.ScanOptions) (*pgx.Conn, error) {
	if options.Credentials.DSN != "" {
		return pgx.Connect(ctx, options.Credentials.DSN)
	}
	return pgx.Connect(ctx, p.buildDSN(target, options))
}

func (p *PgVector) buildDSN(target *model.Target, options model.ScanOptions) string {
	parsed := &url.URL{Scheme: "postgres", Host: engine.TargetAddress(*target)}
	database := options.Credentials.Database
	if database == "" {
		database = strings.TrimPrefix(target.Path, "/")
	}
	if database != "" {
		parsed.Path = "/" + database
	}
	if options.Credentials.Username != "" {
		parsed.User = url.UserPassword(options.Credentials.Username, options.Credentials.Password)
	}
	query := parsed.Query()
	sslMode := "prefer"
	if target.TLS {
		sslMode = "require"
	}
	connectTimeout := maxInt(int(options.Timeout.Seconds()), 1)
	if connectTimeout > 5 {
		connectTimeout = 5
	}
	query.Set("sslmode", sslMode)
	query.Set("connect_timeout", strconv.Itoa(connectTimeout))
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (p *PgVector) scalar(ctx context.Context, conn *pgx.Conn, sql string, args ...any) string {
	row := conn.QueryRow(ctx, sql, args...)
	var value any
	if err := row.Scan(&value); err != nil {
		return ""
	}
	return String(value)
}

func (p *PgVector) vectorTables(ctx context.Context, conn *pgx.Conn) (map[string]vectorTable, error) {
	sql := `SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod)
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_type t ON t.oid = a.atttypid
WHERE t.typname IN ('vector','halfvec','sparsevec','bit')
  AND a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog','information_schema')`
	rows, err := conn.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := map[string]vectorTable{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		schema := String(values[0])
		table := String(values[1])
		column := String(values[2])
		dataType := String(values[3])
		qualified := schema + "." + table
		group := groups[qualified]
		group.schema = schema
		group.table = table
		group.qualified = qualified
		group.columns = append(group.columns, vectorColumn{name: column, dataType: dataType, vector: true})
		groups[qualified] = group
	}
	return groups, rows.Err()
}

func (p *PgVector) describe(ctx context.Context, conn *pgx.Conn, target *model.Target, group vectorTable) *model.Collection {
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorPgVector,
		Name:      group.table,
		Namespace: group.schema,
		Status:    "ready",
		IndexType: "ivfflat",
		CreatedAt: time.Now().UTC(),
	}
	if estimate := p.scalar(ctx, conn, fmt.Sprintf("SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass('%s')", group.qualified)); estimate != "" {
		if count, ok := Integer(estimate); ok {
			collection.PointCount = count
		}
	}
	fields := make([]model.Field, 0, 8)
	columnSQL := `SELECT column_name, data_type, udt_name
FROM information_schema.columns
WHERE table_schema = $1 AND table_name = $2
ORDER BY ordinal_position`
	rows, err := conn.Query(ctx, columnSQL, group.schema, group.table)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			values, valuesErr := rows.Values()
			if valuesErr != nil {
				continue
			}
			name := String(values[0])
			dataType := String(values[1])
			udtName := String(values[2])
			field := Field(name, dataType)
			field.DataType = udtName
			if _, isVector := pgVectorTypes[udtName]; isVector {
				if dimension := parseDimension(dataType); dimension > 0 {
					field.Dimension = dimension
					collection.Dimension = dimension
				}
			}
			fields = append(fields, field)
		}
	}
	primary := p.scalar(ctx, conn, `SELECT a.attname
FROM pg_index i
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
WHERE i.indrelid = to_regclass($1) AND i.indisprimary
ORDER BY array_position(i.indkey, a.attnum) NULLS LAST
LIMIT 1`, group.qualified)
	indexes := make([]model.Index, 0, 2)
	indexRows, indexErr := conn.Query(ctx, `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename = $2`, group.schema, group.table)
	if indexErr == nil {
		defer indexRows.Close()
		for indexRows.Next() {
			values, _ := indexRows.Values()
			name := String(values[0])
			definition := String(values[1])
			lower := strings.ToLower(definition)
			indexType := ""
			switch {
			case strings.Contains(lower, "hnsw"):
				indexType = "hnsw"
			case strings.Contains(lower, "ivfflat"):
				indexType = "ivfflat"
			}
			metric := ""
			switch {
			case strings.Contains(lower, "vector_l2_ops"):
				metric = "l2"
			case strings.Contains(lower, "vector_cosine_ops"):
				metric = "cosine"
			case strings.Contains(lower, "vector_ip_ops"):
				metric = "ip"
			}
			if indexType == "" && metric == "" {
				continue
			}
			if collection.Metric == "" {
				collection.Metric = metric
			}
			if collection.IndexType == "" {
				collection.IndexType = indexType
			}
			indexes = append(indexes, model.Index{
				Name:      name,
				Type:      indexType,
				Metric:    metric,
				Dimension: collection.Dimension,
				Params:    map[string]any{"definition": definition},
			})
		}
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{
		"primary_key": primary,
		"relation":    group.qualified,
	})
	return collection
}

func (p *PgVector) rows(ctx context.Context, conn *pgx.Conn, target *model.Target, collection *model.Collection, group vectorTable, dump model.DumpOptions) ([]*model.Record, error) {
	columns, err := p.tableColumns(ctx, conn, group)
	if err != nil {
		return nil, err
	}
	selectList := make([]string, 0, len(columns))
	vectorNames := make([]string, 0, 2)
	for _, column := range columns {
		quoted := pgx.Identifier{column.name}.Sanitize()
		if column.vector {
			selectList = append(selectList, quoted+"::text AS "+quoted)
			vectorNames = append(vectorNames, column.name)
			continue
		}
		selectList = append(selectList, quoted)
	}
	qualified := pgx.Identifier{group.schema, group.table}.Sanitize()
	sql := fmt.Sprintf("SELECT %s FROM %s LIMIT $1 OFFSET $2", strings.Join(selectList, ", "), qualified)
	records := make([]*model.Record, 0, dump.BatchSize)
	offset := 0
	for len(records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(records); remaining < limit {
			limit = remaining
		}
		rows, err := conn.Query(ctx, sql, limit, offset)
		if err != nil {
			return records, err
		}
		rowCount := 0
		descriptions := rows.FieldDescriptions()
		for rows.Next() {
			values, err := rows.Values()
			if err != nil {
				rows.Close()
				return records, err
			}
			payload := map[string]any{}
			vector := VectorData{}
			externalID := ""
			for index, value := range values {
				name := string(descriptions[index].Name)
				converted := pgValue(value)
				if containsString(vectorNames, name) {
					if dump.IncludeVectors && vector.Empty() {
						vector = ParseVector(converted, dump.MaxVectorValues)
					}
					continue
				}
				payload[name] = converted
				if externalID == "" && index == 0 {
					externalID = String(converted)
				}
			}
			if externalID == "" {
				externalID = fmt.Sprintf("offset-%d", offset+rowCount)
			}
			records = append(records, p.Record(target, collection, externalID, payload, vector, dump.MaxPayloadBytes))
			rowCount++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return records, err
		}
		if rowCount < limit {
			break
		}
		offset += rowCount
	}
	return records, nil
}

func (p *PgVector) tableColumns(ctx context.Context, conn *pgx.Conn, group vectorTable) ([]vectorColumn, error) {
	sql := `SELECT column_name, udt_name
FROM information_schema.columns
WHERE table_schema = $1 AND table_name = $2
ORDER BY ordinal_position`
	rows, err := conn.Query(ctx, sql, group.schema, group.table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make([]vectorColumn, 0, 8)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		name := String(values[0])
		udtName := String(values[1])
		_, isVector := pgVectorTypes[udtName]
		columns = append(columns, vectorColumn{name: name, dataType: udtName, vector: isVector})
	}
	return columns, rows.Err()
}

func parseDimension(dataType string) int {
	start := strings.Index(dataType, "(")
	end := strings.Index(dataType, ")")
	if start < 0 || end <= start {
		return 0
	}
	value, err := strconv.Atoi(strings.TrimSpace(dataType[start+1 : end]))
	if err != nil {
		return 0
	}
	return value
}

func pgValue(value any) any {
	switch typed := value.(type) {
	case []byte:
		return string(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	default:
		return value
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
