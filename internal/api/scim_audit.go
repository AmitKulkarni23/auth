package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

func scimActor(r *http.Request) *models.User {
	return &models.User{Email: storage.NullString("scim:" + scim.TokenPrefix(r.Context()))}
}

func (a *API) auditSCIM(tx *storage.Connection, r *http.Request, actor *models.User, action models.AuditAction, providerID uuid.UUID, traits map[string]any) error {
	traits["sso_provider_id"] = providerID
	traits["outcome"] = "success"
	return models.NewAuditLogEntry(a.config.AuditLog, r, tx, actor, action, utilities.GetIPAddress(r), traits)
}

func (a *API) deleteSCIMUsers(tx *storage.Connection, r *http.Request, actor *models.User, userID uuid.UUID) error {
	rows, err := models.SoftDeleteSCIMUsersByUserID(tx, userID)
	if err != nil {
		return err
	}
	for i := range rows {
		if err := a.removeSCIMUserFromGroups(tx, r, actor, &rows[i]); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) removeSCIMUserFromGroups(tx *storage.Connection, r *http.Request, actor *models.User, row *models.SCIMUser) error {
	groupIDs, err := models.RemoveSCIMUserFromGroups(tx, row.ID)
	if err != nil {
		return err
	}
	for _, groupID := range groupIDs {
		if err := a.auditSCIMMember(tx, r, actor, models.SCIMGroupMemberRemovedAction, row.SSOProviderID, groupID, row.ID); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) auditSCIMMember(tx *storage.Connection, r *http.Request, actor *models.User, action models.AuditAction, providerID, groupID, scimUserID uuid.UUID) error {
	return a.auditSCIM(tx, r, actor, action, providerID, map[string]any{
		"scim_group_id": groupID,
		"scim_user_id":  scimUserID,
	})
}
