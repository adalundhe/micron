package stores

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/adalundhe/micron/models"
)

var _ models.UserRepository = (*DbUserRepository)(nil)

type DbUserRepository struct {
	db *bun.DB
}

var Users *DbUserRepository

func NewDbUserRepository(db *bun.DB) *DbUserRepository {
	return &DbUserRepository{db: db}
}

// Insert inserts a new user into the database
func (r *DbUserRepository) Insert(ctx context.Context, u *models.User) (*models.User, error) {
	_, err := r.db.NewInsert().Model(u).Exec(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.UpdateEmails(ctx, u); err != nil {
		return nil, err
	}
	if err := r.PopulateEmails(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (r *DbUserRepository) UpdateEmails(ctx context.Context, user *models.User) error {

	if user.Emails != nil && len(*user.Emails) > 0 {
		var userEmails []models.UserEmails
		for _, email := range *user.Emails {
			userEmails = append(userEmails, models.UserEmails{
				UserID: user.ID,
				Email:  email,
			})
		}
		_, err := r.db.NewInsert().Model(&userEmails).On("CONFLICT (email) DO NOTHING").Exec(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *DbUserRepository) PopulateEmails(ctx context.Context, u *models.User) error {
	var emails []models.UserEmails
	q := r.db.NewSelect().Model(&emails).Where("user_id = ?", u.ID).Order("email ASC")
	if err := q.Scan(ctx); err != nil {
		return err
	}
	var userEmails []string
	for _, email := range emails {
		userEmails = append(userEmails, email.Email)
	}
	u.Emails = &userEmails
	return nil
}

// Upsert updates or inserts a user into the database
func (r *DbUserRepository) Upsert(ctx context.Context, u *models.User) (*models.User, error) {
	_, err := r.db.NewInsert().Model(u).On("CONFLICT (id) DO UPDATE").Set("usernames = EXCLUDED.usernames").Exec(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.UpdateEmails(ctx, u); err != nil {
		return nil, err
	}
	if err := r.PopulateEmails(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (r *DbUserRepository) Update(ctx context.Context, u *models.User) (*models.User, error) {
	_, err := r.db.NewUpdate().Model(u).WherePK().Exec(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.UpdateEmails(ctx, u); err != nil {
		return nil, err
	}
	if err := r.PopulateEmails(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Delete deletes a user from the database
// TODO: implement this method
func (r *DbUserRepository) Delete(ctx context.Context, u *models.User) (bool, error) {
	return false, nil
}

func (r *DbUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var (
		userEmail models.UserEmails
		user      models.User
	)
	q := r.db.NewSelect().Model(&userEmail).Where("email = ?", email)
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to get user email (%s): %w", email, err)
	}
	q = r.db.NewSelect().Model(&user).Where("id = ?", userEmail.UserID)
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to get user by id (%d): %w", userEmail.UserID, err)
	}

	if err := r.PopulateEmails(ctx, &user); err != nil {
		return nil, fmt.Errorf("failed to populate emails for user (%d): %w", user.ID, err)
	}
	return &user, nil
}

func (r *DbUserRepository) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	var user models.User
	q := r.db.NewSelect().Model(&user).Where("id = ?", id)
	if err := q.Scan(ctx); err != nil {
		return nil, err
	}
	if err := r.PopulateEmails(ctx, &user); err != nil {
		return nil, err
	}
	return &user, nil
}
