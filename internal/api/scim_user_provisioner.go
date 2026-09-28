package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type scimUserProvisioner struct {
	api *API
}

func newSCIMUserProvisioner(api *API) scim.UserProvisioner {
	return &scimUserProvisioner{api: api}
}

func (p *scimUserProvisioner) Create(ctx context.Context, providerID uuid.UUID, input scim.UserInput) (*models.SCIMUser, error) {
	if input.Email == "" {
		return nil, errEmailRequired()
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := p.api.db.WithContext(ctx)
	if err := p.beforeCreate(r, db, providerID, input); err != nil {
		return nil, err
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.LockAccountLinking(tx, "sso:"+providerID.String(), input.Email); terr != nil {
			return terr
		}
		var terr error
		if row, terr = models.CreateSCIMUser(tx, providerID, input.Resource); terr != nil {
			return terr
		}
		if created, terr = p.linkNew(tx, row, input); terr != nil {
			return terr
		}
		return p.auditUser(tx, r, models.SCIMUserCreatedAction, row)
	})
	if err != nil {
		return nil, err
	}
	p.afterCreate(r, db, created)
	return row, nil
}

func (p *scimUserProvisioner) Replace(ctx context.Context, providerID, id uuid.UUID, input scim.UserInput, updatedAt *time.Time) (*models.SCIMUser, error) {
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := p.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, providerID, id)
	if err != nil {
		return nil, err
	}
	if existing.UserID == nil {
		if input.Email == "" {
			return nil, errEmailRequired()
		}
		if err := p.beforeCreate(r, db, providerID, input); err != nil {
			return nil, err
		}
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.LockAccountLinking(tx, "sso:"+providerID.String(), input.Email); terr != nil {
			return terr
		}
		if existing.UserID != nil {
			if terr := models.LockUserForSCIM(tx, *existing.UserID); terr != nil {
				return terr
			}
		}
		old, terr := models.FindSCIMUserForUpdate(tx, providerID, id)
		if terr != nil {
			return terr
		}
		if row, terr = models.ReplaceSCIMUser(tx, providerID, id, input.Resource, updatedAt); terr != nil {
			return terr
		}
		if created, terr = p.sync(tx, providerID, old, row, input); terr != nil {
			return terr
		}
		return p.auditUser(tx, r, userAuditAction(old, row), row)
	})
	if err != nil {
		return nil, err
	}
	p.afterCreate(r, db, created)
	return row, nil
}

func (p *scimUserProvisioner) sync(tx *storage.Connection, providerID uuid.UUID, old, row *models.SCIMUser, input scim.UserInput) (*models.User, error) {
	if old.UserID == nil {
		if input.Email == "" {
			return nil, errEmailRequired()
		}
		return p.linkNew(tx, row, input)
	}

	user, err := models.FindUserByID(tx, *old.UserID)
	if err != nil {
		return nil, err
	}
	if from := userName(old.Resource); from != input.UserName {
		data := map[string]any{"sub": input.UserName}
		if input.Email != "" {
			data["email"] = input.Email
		}
		err := models.RenameSCIMIdentity(tx, user.ID, "sso:"+providerID.String(), from, input.UserName, data)
		if errors.Is(err, models.SCIMIdentityNotFoundError{}) {
			logrus.WithField("user_id", user.ID).WithField("sso_provider_id", providerID).Warn("scim: SCIM identity not found, rename skipped")
		} else if err != nil {
			return nil, err
		}
	}
	if old.Active && !row.Active {
		return nil, deactivate(tx, user.ID)
	}
	return nil, nil
}

func (p *scimUserProvisioner) Delete(ctx context.Context, providerID, id uuid.UUID, updatedAt *time.Time) error {
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	db := p.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, providerID, id)
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *storage.Connection) error {
		if existing.UserID != nil {
			if err := models.LockUserForSCIM(tx, *existing.UserID); err != nil {
				return err
			}
		}
		row, err := models.DeleteSCIMUser(tx, providerID, id, updatedAt)
		if err != nil {
			return err
		}
		if row.UserID != nil {
			if err := deactivate(tx, *row.UserID); err != nil {
				return err
			}
		}
		if err := p.api.removeSCIMUserFromGroups(tx, r, scimActor(r), row); err != nil {
			return err
		}
		return p.auditUser(tx, r, models.SCIMUserDeletedAction, row)
	})
}

func (p *scimUserProvisioner) linkNew(tx *storage.Connection, row *models.SCIMUser, input scim.UserInput) (*models.User, error) {
	user, isNew, err := p.link(tx, row, input)
	if err != nil {
		return nil, err
	}
	var created *models.User
	if isNew {
		created = user
	}
	if !row.Active {
		return created, deactivate(tx, user.ID)
	}
	return created, nil
}

func (p *scimUserProvisioner) link(tx *storage.Connection, row *models.SCIMUser, input scim.UserInput) (*models.User, bool, error) {
	providerType := "sso:" + row.SSOProviderID.String()
	decision, err := p.decide(tx, providerType, input)
	if err != nil {
		return nil, false, err
	}

	user := decision.User
	switch decision.Decision {
	case models.AccountExists:
	case models.LinkAccount:
		if _, err = p.api.createNewIdentity(tx, user, providerType, identityData(input)); err != nil {
			return nil, false, err
		}
		if err = user.UpdateAppMetaDataProviders(tx); err != nil {
			return nil, false, err
		}
	case models.CreateAccount:
		if user, err = p.newUser(providerType, decision, input); err != nil {
			return nil, false, err
		}
		if user, err = p.api.signupNewUser(tx, user); err != nil {
			return nil, false, err
		}
		if _, err = p.api.createNewIdentity(tx, user, providerType, identityData(input)); err != nil {
			return nil, false, err
		}
		return user, true, models.LinkSCIMUser(tx, row, user.ID)
	case models.MultipleAccounts:
		return nil, false, scimerrors.ErrUniqueness("multiple users share this email in the SSO provider")
	default:
		return nil, false, apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
	}

	return user, false, models.LinkSCIMUser(tx, row, user.ID)
}

func (p *scimUserProvisioner) beforeCreate(r *http.Request, db *storage.Connection, providerID uuid.UUID, input scim.UserInput) error {
	if !p.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := "sso:" + providerID.String()
	decision, err := p.decide(db, providerType, input)
	if err != nil || decision.Decision != models.CreateAccount {
		return err
	}
	user, err := p.newUser(providerType, decision, input)
	if err != nil {
		return err
	}
	return hookError(p.api.triggerBeforeUserCreated(r, db, user))
}

func (p *scimUserProvisioner) afterCreate(r *http.Request, db *storage.Connection, user *models.User) {
	if user == nil {
		return
	}
	if err := p.api.triggerAfterUserCreated(r, db, user); err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Error("scim: after user created hook failed")
	}
}

func scimRequest(ctx context.Context) (*http.Request, error) {
	r := scimRequestKey.Value(ctx)
	if r == nil {
		return nil, apierrors.NewInternalServerError("SCIM request missing from context")
	}
	return r.WithContext(ctx), nil
}

func (p *scimUserProvisioner) decide(conn *storage.Connection, providerType string, input scim.UserInput) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: input.Email, Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, p.api.config, emails, p.api.config.JWT.Aud, providerType, input.UserName)
}

func (p *scimUserProvisioner) newUser(providerType string, decision models.AccountLinkingResult, input scim.UserInput) (*models.User, error) {
	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      p.api.config.JWT.Aud,
		Data:     identityData(input),
	}
	user, err := params.ToUserModel(true)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	user.EmailConfirmedAt = &now
	return user, nil
}

func (p *scimUserProvisioner) auditUser(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) error {
	traits := map[string]any{
		"scim_user_id": row.ID,
		"user_name":    row.UserName,
		"active":       row.Active,
	}
	if row.UserID != nil {
		traits["user_id"] = *row.UserID
	}
	return p.api.auditSCIM(tx, r, scimActor(r), action, row.SSOProviderID, traits)
}

func userAuditAction(before, after *models.SCIMUser) models.AuditAction {
	switch {
	case before.Active && !after.Active:
		return models.SCIMUserDeactivatedAction
	case !before.Active && after.Active:
		return models.SCIMUserReactivatedAction
	}
	return models.SCIMUserUpdatedAction
}

func deactivate(tx *storage.Connection, userID uuid.UUID) error {
	if err := models.LockUserForSCIM(tx, userID); err != nil {
		return err
	}
	return models.Logout(tx, userID)
}

func errSCIMSignupDisabled() error {
	return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeSignupDisabled, "Signups not allowed while SCIM provisioning is enabled for this SSO provider")
}

func errEmailRequired() error {
	return scimerrors.ErrInvalidValue(`"emails" is required`)
}

func identityData(input scim.UserInput) map[string]any {
	return map[string]any{
		"sub":            input.UserName,
		"email":          input.Email,
		"email_verified": true,
	}
}

func userName(resource []byte) string {
	var r struct {
		UserName string `json:"userName"`
	}
	_ = json.Unmarshal(resource, &r)
	return r.UserName
}

func hookError(err error) error {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return err
}
