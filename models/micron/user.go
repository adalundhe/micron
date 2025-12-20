package micronapi

// GetUserByEmailQuery represents the query parameters for getting a user by email
type GetUserByEmailQuery struct {
	Email string `path:"email"`
}
