package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/rbac"
)

var (
	ErrDomainNotSupported = errors.New("domain should not be used")
)

// RoleManager is a custom role manager, implements casbin RoleManager interface
type RoleManager struct {
	idp          idp.IdentityProvider
	validDomains []string
	activeCheck  func(u *idp.IdpUser) bool
}

var _ rbac.RoleManager = (*RoleManager)(nil)

func NewRoleManager(idpProvider idp.IdentityProvider, validDomains []string, activeCheck func(u *idp.IdpUser) bool) *RoleManager {
	return &RoleManager{
		idp:          idpProvider,
		validDomains: validDomains,
		activeCheck:  activeCheck,
	}
}

// GetRoles gets the roles that a user inherits. domain is not used
func (r RoleManager) GetRoles(userEmail string, domain ...string) ([]string, error) {
	slog.Debug("RoleManager GetRoles called", slog.String("userEmail", userEmail), slog.Any("domain", domain))

	if len(domain) > 1 {
		return nil, ErrDomainNotSupported
	}

	ctx := idp.WithIdpEmail(context.Background(), userEmail)

	user, err := r.idp.GetUserByEmail(ctx, userEmail)
	if err != nil {
		slog.Error("Failed to get user info", slog.Any("error", err))
		return nil, err
	}

	if !user.IsActive(r.activeCheck) {
		slog.Error("User is not active", slog.String("userEmail", userEmail))
		return nil, fmt.Errorf("user %s is not active", userEmail)
	}

	groups, err := r.idp.ListUserGroups(ctx, userEmail)
	if err != nil {
		slog.Error("Failed to get user groups", slog.Any("error", err))
		return nil, err
	}

	roles := make([]string, 0, len(groups))
	for _, group := range groups {
		roles = append(roles, group.Name)
	}

	return roles, nil
}

// GetUsers gets users that inherits a role. domain is not used
func (r RoleManager) GetUsers(groupName string, domain ...string) ([]string, error) {
	if len(domain) > 1 {
		return nil, ErrDomainNotSupported
	}

	users, err := r.idp.ListGroupMembersByName(context.Background(), groupName)
	if err != nil {
		slog.Error("Failed to get group users", slog.Any("error", err))
		return nil, err
	}

	userEmails := make([]string, 0, len(users))
	for _, user := range users {
		userEmails = append(userEmails, user.Email)
	}

	return userEmails, nil
}

// BuildRelationship not implemented
func (r RoleManager) BuildRelationship(name1 string, name2 string, domain ...string) error {
	panic("BuildRelationship not implemented")
}

// GetDomains not implemented
func (r RoleManager) GetDomains(name string) ([]string, error) {
	panic("GetDomains not implemented")
}

// GetAllDomains not implemented
func (r RoleManager) GetAllDomains() ([]string, error) {
	panic("GetAllDomains not implemented")
}

// SetLogger not implemented
func (r RoleManager) SetLogger(logger log.Logger) {
	panic("SetLogger not implemented")
}

// Match not implemented
func (r RoleManager) Match(str string, pattern string) bool {
	panic("Match not implemented")
}

// AddMatchingFunc not implemented
func (r RoleManager) AddMatchingFunc(name string, fn rbac.MatchingFunc) {
	panic("AddMatchingFunc not implemented")
}

// AddDomainMatchingFunc not implemented
func (r RoleManager) AddDomainMatchingFunc(name string, fn rbac.MatchingFunc) {
	panic("AddDomainMatchingFunc not implemented")
}

// Clear not implemented
func (r RoleManager) Clear() error {
	return nil
}

// AddLink not implemented
func (r RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	panic("AddLink not implemented")
}

// DeleteLink not implemented
func (r RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	panic("DeleteLink not implemented")
}

func (r *RoleManager) DeleteDomain(string) error {
	panic("DeleteDomain not implemented")
}

func (r *RoleManager) GetImplicitRoles(name string, domain ...string) ([]string, error) {
	panic("GetImplicitRoles not implemented")
}

func (r *RoleManager) GetImplicitUsers(name string, domain ...string) ([]string, error) {
	panic("GetImplicitUsers not implemented")
}

// HasLink determines whether role: name1 inherits role: name2, domain is not used
func (r RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	if len(domain) >= 1 {
		slog.Error("Error determining if user inherits role", slog.Any("error", ErrDomainNotSupported), slog.String("name1", name1), slog.String("name2", name2), slog.Any("domain", domain))
		return false, ErrDomainNotSupported
	}

	// check if name2 is an exact user. if so compare to name1
	if r.validateDomain(name2) {
		name1 = strings.ToLower(name1)
		name2 = strings.ToLower(name2)
		return name1 == name2, nil
	}

	roles, err := r.GetRoles(name1)
	if err != nil {
		slog.Error("Error determining if user inherits role", slog.Any("error", err), slog.String("name1", name1), slog.String("name2", name2), slog.Any("domain", domain))
		return false, err
	}
	for _, role := range roles {
		if role == name2 {
			return true, nil
		}
	}
	return false, nil
}

func (r RoleManager) validateDomain(query string) bool {
	for _, domain := range r.validDomains {
		if strings.HasSuffix(query, domain) {
			return true
		}
	}

	return false
}

// PrintRoles not implemented
func (r RoleManager) PrintRoles() error {
	panic("PrintRoles not implemented")
}
