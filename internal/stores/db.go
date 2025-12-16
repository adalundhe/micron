package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/adalundhe/micron/internal/config"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/uptrace/bun/extra/bundebug"
)

var (
	ErrUnknownDBType = errors.New("unknown database type")

	defaultSqliteDSN = "file::memory:?cache=shared"
)

type PaginationType int

const (
	PaginationTypeNext PaginationType = iota
	PaginationTypePrev
)

type Cursor struct {
	Start          int64
	End            int64
	PaginationType PaginationType
}

type NoRowsError struct {
	Err error
}

func (n NoRowsError) Error() string {
	return fmt.Sprintf("no rows found: %v", n.Err)
}

// NewDB creates a new bun.DB instance based on the provided DbType and DSN.
// Supported types are "postgres" and "sqlite".
// Note: for sqlite, if the DSN is ignored and a memory database is used.
func NewDB(t config.DbType, dsn string, username string, password string) (*bun.DB, error) {
	switch t {
	case config.Postgres:
		conn := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithUser(username), pgdriver.WithPassword(password)))
		if err := conn.Ping(); err != nil {
			return nil, err
		}
		return bun.NewDB(conn, pgdialect.New()), nil
	case config.Sqlite:
		slog.Warn("WARNING: sqlite is not suitable for use outside of testing")
		slog.Warn("flyway migrations are not supported for sqlite. You will need to manually manage the schema")
		if dsn == "" {
			dsn = defaultSqliteDSN
		}
		conn, err := sql.Open(sqliteshim.ShimName, dsn)
		if err != nil {
			return nil, err
		}
		return bun.NewDB(conn, sqlitedialect.New()), nil
	}

	return nil, ErrUnknownDBType
}

// MustNewDB is a helper function that wraps NewDB and panics on error.
// Use it in tests.
func MustNewDB(t config.DbType, dsn string, username string, password string) *bun.DB {
	db, err := NewDB(t, dsn, username, password)
	if err != nil {
		panic(err)
	}
	return db
}

func MustNewDbWithDebug(t config.DbType, dsn string, username string, password string) *bun.DB {
	db := MustNewDB(t, dsn, username, password)
	db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
	return db
}

func IdPagination(query *bun.SelectQuery, cursor *Cursor) (*bun.SelectQuery, error) {
	switch cursor.PaginationType {
	case PaginationTypeNext:
		query = query.Where("id > ?", cursor.End).Order("id ASC")
	case PaginationTypePrev:
		if cursor.Start <= 1 {
			query = query.Order("id DESC")
		} else if cursor.Start == cursor.End {
			// Handle the case where there's only one result
			query = query.Where("id <= ?", cursor.Start).Order("id DESC")
		} else {
			query = query.Where("id < ?", cursor.Start).Order("id DESC")
		}
	default:
		return nil, fmt.Errorf("invalid pagination type %v", cursor.PaginationType)
	}
	return query, nil
}
