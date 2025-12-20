package idp

import (
	"context"
	"errors"

	"github.com/adalundhe/micron/models"
)

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrUserRequestInvalid     = errors.New("user id or email is required")
	ErrGroupNotFound          = errors.New("group not found")
	ErrGroupRequestInvalid    = errors.New("group id or name is required")
	ErrTokenAcquisitionFailed = errors.New("failed to acquire access token")
	ErrInvalidConfiguration   = errors.New("invalid provider configuration")
)

// IdpUser represents a user in the identity provider
type IdpUser struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// IsActive returns true if the user is considered active/enabled
func (u *IdpUser) IsActive(check func(u *IdpUser) bool) bool {

	if check == nil {
		return true
	}

	return check(u)
}

// NewIdpUser creates a new IdpUser with the specified provider type
func NewIdpUser(providerType, id, status, firstName, lastName, email, displayName, secondaryEmail string) *IdpUser {
	return &IdpUser{
		ID:          id,
		Status:      status,
		FirstName:   firstName,
		LastName:    lastName,
		Email:       email,
		DisplayName: displayName,
	}
}

// IdpGroup represents a group in the identity provider
type IdpGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type idpEmailKey struct{}

func WithIdpEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, idpEmailKey{}, email)
}

// IdentityProvider defines the interface for identity provider operations
// This interface supports the common operations across different identity providers.
type IdentityProvider interface {
	// User operations
	Verify(u *IdpUser) error
	CheckUserActive(u *IdpUser) bool
	GetUserByEmail(ctx context.Context, email string) (*IdpUser, error)
	GetUserById(ctx context.Context, userId string) (*IdpUser, error)
	ListUserGroups(ctx context.Context, email string) ([]*IdpGroup, error)

	// Group operations
	GetGroupByName(ctx context.Context, name string) (*IdpGroup, error)
	GetGroupById(ctx context.Context, groupId string) (*IdpGroup, error)

	ListGroupMembersById(ctx context.Context, groupID string) ([]*IdpUser, error)
	ListGroupMembersByName(ctx context.Context, groupName string) ([]*IdpUser, error)

	// Connection verification
	VerifyConnection(ctx context.Context) error

	// Cache management
	ClearCache() error

	// Provider identification
	GetProvider(ctx context.Context) (models.OwnerProvider, error)
}

type IdentityProviderImpl struct{}
