package data

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const dbTimeout = time.Second * 3

var db *sql.DB

func New(dbPool *sql.DB) Models {
	db = dbPool
	return Models{
		User:   User{},
		Token:  Token{},
		Book:   Book{},
		Author: Author{},
	}
}

type Models struct {
	User   User
	Token  Token
	Book   Book
	Author Author
	Genre  Genre
}

type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Token     Token     `json:"token"`
	Active    int       `json:"active"`
}

func (u *User) GetAll() ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := `SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at,
	case
		when (select count(id) from tokens t where user_id = users.id and t.expiry > NOW()) > 0 then 1
		else 0
	end as has_token
	FROM users ORDER BY last_name`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var users []*User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Password, &user.Active, &user.CreatedAt, &user.UpdatedAt, &user.Token.ID)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, nil
}

func (u *User) GetByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE email = $1"

	row := db.QueryRowContext(ctx, query, email)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Password, &user.Active, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (u *User) GetByID(id int) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE id = $1"

	row := db.QueryRowContext(ctx, query, id)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Password, &user.Active, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (user *User) Create() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "INSERT INTO users (email, first_name, last_name, password, user_active) VALUES ($1, $2, $3, $4, $5) RETURNING id"

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	var newID int

	err = db.QueryRowContext(ctx, query, user.Email, user.FirstName, user.LastName, hashedPassword).Scan(&newID)
	if err != nil {
		return 0, err
	}
	return newID, nil
}

func (u *User) Update() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "UPDATE users SET email = $1, first_name = $2, last_name = $3, user_active = $4, updated_at = $5 WHERE id = $6"

	_, err := db.ExecContext(ctx, query, u.Email, u.FirstName, u.LastName, u.Active, time.Now(), u.ID)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) Delete() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "DELETE FROM users WHERE id = $1"

	_, err := db.ExecContext(ctx, query, u.ID)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) DeleteByID(id int) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "DELETE FROM users WHERE id = $1"

	_, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) ResetPassword(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	query := "UPDATE users SET password = $1, updated_at = $2 WHERE id = $3"

	_, err = db.ExecContext(ctx, query, hashedPassword, time.Now(), u.ID)

	if err != nil {
		return err
	}

	return nil
}

func (u *User) PasswordMatches(password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

type Token struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	TokenHash []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Expiry    time.Time `json:"expiry"`
}

func (t *Token) GetByToken(plainText string) (*Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "SELECT id, user_id, email, token, token_hash, created_at, updated_at, expiry FROM tokens WHERE token = $1"

	row := db.QueryRowContext(ctx, query, plainText)
	var token Token
	err := row.Scan(&token.ID, &token.UserID, &token.Email, &token.Token, &token.TokenHash, &token.CreatedAt, &token.UpdatedAt, &token.Expiry)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (t *Token) GetUserByToken(token Token) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	query := "SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE id = $1"

	row := db.QueryRowContext(ctx, query, token.UserID)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Password, &user.Active, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (t *Token) GenerateToken(userID int, ttl time.Duration) (*Token, error) {
	token := &Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
	}

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)

	if err != nil {
		return nil, err
	}

	token.Token = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	hash := sha256.Sum256(([]byte(token.Token)))
	token.TokenHash = hash[:]

	return token, nil
}

func (t *Token) AuthenticateToken(r *http.Request) (*User, error) {
	authorizationHeader := r.Header.Get("Authorization")

	if len(authorizationHeader) == 0 {
		return nil, errors.New("authorization header not found")
	}

	headerParts := strings.Split(authorizationHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return nil, errors.New("invalid Authorization header")
	}

	token := headerParts[1]

	if len(token) != 26 {
		return nil, errors.New("invalid token length")
	}

	tkn, err := t.GetByToken(token)

	if err != nil {
		return nil, errors.New("could not find token")
	}

	if tkn.Expiry.Before(time.Now()) {
		return nil, errors.New("Token has expired")
	}

	user, err := tkn.GetUserByToken(*tkn)

	if err != nil {
		return nil, errors.New("could not find user")
	}

	if user.Active == 0 {
		return nil, errors.New("user is not active")
	}
	return user, nil
}

func (t *Token) Insert(token Token, u User) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	stmt := "DELETE FROM tokens WHERE user_id = $1"
	_, err := db.ExecContext(ctx, stmt, u.ID)
	if err != nil {
		return err
	}

	token.Email = u.Email

	stmt = "INSERT INTO tokens (user_id, email, token, token_hash, created_at, updated_at, expiry) VALUES ($1, $2, $3, $4, $5, $6, $7)"

	_, err = db.ExecContext(ctx, stmt, token.UserID, token.Email, token.Token, token.TokenHash, time.Now(), time.Now(), token.Expiry)
	if err != nil {
		return err
	}
	return nil
}

func (t *Token) Delete(token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	stmt := "DELETE FROM tokens WHERE token = $1"
	_, err := db.ExecContext(ctx, stmt, token)
	if err != nil {
		return err
	}
	return nil
}

func (t *Token) DeleteByUserID(userID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	stmt := "DELETE FROM tokens WHERE user_id = $1"
	_, err := db.ExecContext(ctx, stmt, userID)
	if err != nil {
		return err
	}
	return nil
}

func (t *Token) ValidToken(token string) (bool, error) {
	if len(token) != 26 {
		return false, errors.New("invalid token length")
	}

	tkn, err := t.GetByToken(token)
	if err != nil {
		return false, errors.New("could not find token")
	}

	_, err = t.GetUserByToken(*tkn)

	if err != nil {
		return false, errors.New("could not find user")
	}

	if tkn.Expiry.Before(time.Now()) {
		t.Delete(t.Token)
		return false, errors.New("token has expired")
	}

	return true, nil
}
