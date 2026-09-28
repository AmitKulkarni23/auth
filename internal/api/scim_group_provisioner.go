package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type scimGroupProvisioner struct {
	api *API
}

func newSCIMGroupProvisioner(api *API) scim.GroupProvisioner {
	return &scimGroupProvisioner{api: api}
}

func (p *scimGroupProvisioner) Create(ctx context.Context, providerID uuid.UUID, input scim.GroupInput) (*models.SCIMGroup, error) {
	return p.save(ctx, models.SCIMGroupCreatedAction, input, func(tx *storage.Connection) (*models.SCIMGroup, error) {
		return models.CreateSCIMGroup(tx, providerID, input.Resource)
	})
}

func (p *scimGroupProvisioner) Replace(ctx context.Context, providerID, id uuid.UUID, input scim.GroupInput, updatedAt *time.Time) (*models.SCIMGroup, error) {
	return p.save(ctx, models.SCIMGroupUpdatedAction, input, func(tx *storage.Connection) (*models.SCIMGroup, error) {
		return models.ReplaceSCIMGroup(tx, providerID, id, input.Resource, updatedAt)
	})
}

func (p *scimGroupProvisioner) Delete(ctx context.Context, providerID, id uuid.UUID, updatedAt *time.Time) error {
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.FindSCIMGroupForUpdate(tx, providerID, id)
		if err != nil {
			return err
		}
		_, removed, err := models.ReplaceSCIMGroupMembers(tx, row, nil)
		if err != nil {
			return err
		}
		if row, err = models.DeleteSCIMGroup(tx, providerID, id, updatedAt); err != nil {
			return err
		}
		if err := p.auditMembers(tx, r, row, nil, removed); err != nil {
			return err
		}
		return p.auditGroup(tx, r, models.SCIMGroupDeletedAction, row)
	})
}

func (p *scimGroupProvisioner) save(ctx context.Context, action models.AuditAction, input scim.GroupInput, write func(tx *storage.Connection) (*models.SCIMGroup, error)) (*models.SCIMGroup, error) {
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	var row *models.SCIMGroup
	err = p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var terr error
		if row, terr = write(tx); terr != nil {
			return terr
		}
		added, removed, terr := models.ReplaceSCIMGroupMembers(tx, row, input.Members)
		if terr != nil {
			return terr
		}
		if terr := p.auditGroup(tx, r, action, row); terr != nil {
			return terr
		}
		return p.auditMembers(tx, r, row, added, removed)
	})
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (p *scimGroupProvisioner) auditGroup(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMGroup) error {
	var resource struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(row.Resource, &resource); err != nil {
		return err
	}
	return p.api.auditSCIM(tx, r, scimActor(r), action, row.SSOProviderID, map[string]any{
		"scim_group_id": row.ID,
		"display_name":  resource.DisplayName,
	})
}

func (p *scimGroupProvisioner) auditMembers(tx *storage.Connection, r *http.Request, row *models.SCIMGroup, added, removed []uuid.UUID) error {
	for _, change := range []struct {
		action models.AuditAction
		ids    []uuid.UUID
	}{
		{models.SCIMGroupMemberAddedAction, added},
		{models.SCIMGroupMemberRemovedAction, removed},
	} {
		for _, id := range change.ids {
			if err := p.api.auditSCIMMember(tx, r, scimActor(r), change.action, row.SSOProviderID, row.ID, id); err != nil {
				return err
			}
		}
	}
	return nil
}
