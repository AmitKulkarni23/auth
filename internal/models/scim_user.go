package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMUser struct {
	ID            uuid.UUID  `db:"id"`
	SSOProviderID uuid.UUID  `db:"sso_provider_id"`
	UserID        *uuid.UUID `db:"user_id"`
	Resource      []byte     `db:"resource"`
	UserName      string     `db:"user_name"`
	ExternalID    *string    `db:"external_id"`
	Active        bool       `db:"active"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at"`
}

const scimUserColumns = "id, sso_provider_id, user_id, resource, user_name, external_id, active, created_at, updated_at, deleted_at"

func (SCIMUser) TableName() string {
	return "scim_users"
}

var scimUsersTable = scimTable{
	name:     SCIMUser{}.TableName(),
	label:    "SCIM user",
	columns:  scimUserColumns,
	nameCol:  "user_name",
	live:     "deleted_at IS NULL",
	notFound: SCIMUserNotFoundError{},
	stale:    SCIMUserStaleError{},
	conflict: SCIMUserConflictError{},
}

func CreateSCIMUser(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMUser, error) {
	return createSCIMRow[SCIMUser](tx, scimUsersTable, providerID, resource)
}

func FindSCIMUser(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	return findSCIMRow[SCIMUser](tx, scimUsersTable, providerID, id, "")
}

func FindSCIMUserForUpdate(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	return findSCIMRow[SCIMUser](tx, scimUsersTable, providerID, id, " FOR UPDATE")
}

func FindSCIMUsers(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMUser, int, error) {
	return findSCIMPage[SCIMUser](tx, scimUsersTable, providerID, query)
}

func ReplaceSCIMUser(tx *storage.Connection, providerID, id uuid.UUID, resource []byte, updatedAt *time.Time) (*SCIMUser, error) {
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND deleted_at IS NULL AND (?::timestamptz IS NULL OR updated_at = ?) RETURNING "+scimUserColumns, user.TableName()),
		string(resource), id, providerID, updatedAt, updatedAt,
	).First(user)
	if err != nil {
		return nil, scimWriteError[SCIMUser](tx, scimUsersTable, err, providerID, id, updatedAt, "replacing")
	}
	return user, nil
}

func DeleteSCIMUser(tx *storage.Connection, providerID, id uuid.UUID, updatedAt *time.Time) (*SCIMUser, error) {
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now(), updated_at = now() WHERE id = ? AND sso_provider_id = ? AND deleted_at IS NULL AND (?::timestamptz IS NULL OR updated_at = ?) RETURNING "+scimUserColumns, user.TableName()),
		id, providerID, updatedAt, updatedAt,
	).First(user)
	if err != nil {
		return nil, scimWriteError[SCIMUser](tx, scimUsersTable, err, providerID, id, updatedAt, "deleting")
	}
	return user, nil
}

func LockUserForSCIM(tx *storage.Connection, userID uuid.UUID) error {
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id = ? FOR UPDATE", (&User{}).TableName()),
		userID,
	).Exec(); err != nil {
		return errors.Wrap(err, "error locking user")
	}
	return nil
}

func SoftDeleteSCIMUsersByUserID(tx *storage.Connection, userID uuid.UUID) ([]SCIMUser, error) {
	rows := []SCIMUser{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now(), updated_at = now() WHERE user_id = ? AND deleted_at IS NULL RETURNING "+scimUserColumns, (&SCIMUser{}).TableName()),
		userID,
	).All(&rows); err != nil {
		return nil, errors.Wrap(err, "error deleting SCIM users by user id")
	}
	return rows, nil
}

func BanDeprovisionedSCIMUsers(tx *storage.Connection, providerID uuid.UUID, until time.Time) (int, error) {
	users, scimUsers := (&User{}).TableName(), (&SCIMUser{}).TableName()
	count, err := tx.RawQuery(
		fmt.Sprintf(
			"UPDATE %[1]q u SET banned_until = ?, updated_at = now() "+
				"WHERE u.id IN (SELECT user_id FROM %[2]q WHERE sso_provider_id = ? AND (deleted_at IS NOT NULL OR NOT active)) "+
				"AND NOT EXISTS (SELECT 1 FROM %[2]q l WHERE l.user_id = u.id AND l.deleted_at IS NULL AND l.active) "+
				"AND (u.banned_until IS NULL OR u.banned_until < ?)",
			users, scimUsers,
		),
		until, providerID, until,
	).ExecWithCount()
	if err != nil {
		return 0, errors.Wrap(err, "error banning deprovisioned SCIM users")
	}
	return count, nil
}

func LinkSCIMUser(tx *storage.Connection, user *SCIMUser, userID uuid.UUID) error {
	if err := LockUserForSCIM(tx, userID); err != nil {
		return err
	}

	linked, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NULL", user.SSOProviderID, userID).Exists(&SCIMUser{})
	if err != nil {
		return errors.Wrap(err, "error finding linked SCIM user")
	}
	if linked {
		return SCIMUserLinkedError{}
	}

	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET user_id = ? WHERE id = ?", user.TableName()),
		userID, user.ID,
	).Exec(); err != nil {
		return errors.Wrap(err, "error linking SCIM user")
	}
	user.UserID = &userID
	return nil
}

func IsSCIMProvisioned(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	provisioned, err := tx.Q().Where("sso_provider_id = ? AND user_id = ?", providerID, userID).Exists(&SCIMUser{})
	if err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return provisioned, nil
}

func IsSCIMManaged(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	managed, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NULL", providerID, userID).Exists(&SCIMUser{})
	if err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return managed, nil
}

func IsSCIMDeprovisioned(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	provisioned, err := IsSCIMProvisioned(tx, providerID, userID)
	if err != nil {
		return false, err
	}
	if !provisioned {
		return false, nil
	}
	live, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NULL AND active", providerID, userID).Exists(&SCIMUser{})
	if err != nil {
		return false, errors.Wrap(err, "error finding live SCIM user")
	}
	return !live, nil
}

func IsSCIMUserDeprovisionedForUpdate(tx *storage.Connection, userID uuid.UUID) (bool, error) {
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id = ? FOR NO KEY UPDATE", (&User{}).TableName()),
		userID,
	).Exec(); err != nil {
		return false, errors.Wrap(err, "error locking user")
	}
	rows := []struct {
		Active    bool       `db:"active"`
		DeletedAt *time.Time `db:"deleted_at"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT active, deleted_at FROM %q WHERE user_id = ?", (&SCIMUser{}).TableName()),
		userID,
	).All(&rows); err != nil {
		return false, errors.Wrap(err, "error finding SCIM users")
	}
	for _, row := range rows {
		if row.DeletedAt == nil && row.Active {
			return false, nil
		}
	}
	return len(rows) > 0, nil
}

func RenameSCIMIdentity(tx *storage.Connection, userID uuid.UUID, provider, from, to string, data map[string]any) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "error encoding identity data")
	}
	count, err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET provider_id = ?, identity_data = identity_data || ?::jsonb, updated_at = now() WHERE user_id = ? AND provider = ? AND provider_id = ?", (&Identity{}).TableName()),
		to, string(encoded), userID, provider, from,
	).ExecWithCount()
	if err != nil {
		if isUniqueViolation(err) {
			return SCIMUserConflictError{}
		}
		return errors.Wrap(err, "error renaming SCIM identity")
	}
	if count == 0 {
		return SCIMIdentityNotFoundError{}
	}
	return nil
}

func LockAccountLinking(tx *storage.Connection, providerType, email string) error {
	key := providerType + "|" + strings.ToLower(email)
	if err := tx.RawQuery("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", key).Exec(); err != nil {
		return errors.Wrap(err, "error locking account linking")
	}
	return nil
}
