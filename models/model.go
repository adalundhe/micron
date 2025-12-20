package models

import (
	"context"
	"strings"

	"github.com/uptrace/bun"
)

type OwnerProvider string

type User struct {
	bun.BaseModel `bun:"table:user_info"`
	ID            int64   `bun:"id,pk,autoincrement"`
	IDPId         *string `bun:"idp_id"`
	// keeping this around for bun
	email       *string   `bun:"email"`
	UserNames   *[]string `bun:"usernames,array"`
	FirstName   *string   `bun:"first_name"`
	LastName    *string   `bun:"last_name"`
	DisplayName *string   `bun:"display_name"`
	// we will use this to populate the UserEmails table
	Emails *[]string `bun:"-"`
}

func (u *User) GetFirstEmail(domains ...string) string {
	if u.Emails == nil || len(*u.Emails) == 0 {
		return ""
	}

	// If no domains specified, return the first email
	if len(domains) == 0 {
		return (*u.Emails)[0]
	}

	// Look for an email that matches one of the specified domains
	for _, email := range *u.Emails {
		for _, domain := range domains {
			if strings.HasSuffix(strings.ToLower(email), strings.ToLower(domain)) {
				return email
			}
		}
	}

	// If no email matches the specified domains, return empty string to fail fast
	return ""
}

type UserEmails struct {
	bun.BaseModel `bun:"table:user_emails"`
	UserID        int64  `bun:"user_id"`
	Email         string `bun:"email"`
}

// UserRepository is the interface for user storage
type UserRepository interface {
	Insert(ctx context.Context, u *User) (*User, error)
	Upsert(ctx context.Context, u *User) (*User, error)
	Delete(ctx context.Context, u *User) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}
