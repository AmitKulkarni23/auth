package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const scimProviderDeletedBan = 100 * 365 * 24 * time.Hour

type AdminSCIMTokenCreateParams struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

type AdminSCIMTokenCreateResponse struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
	*models.SCIMToken
}

type AdminSCIMTokenListResponse struct {
	Tokens []models.SCIMToken `json:"tokens"`
}

type AdminSCIMStatusResponse struct {
	Enabled bool               `json:"enabled"`
	BaseURL string             `json:"base_url"`
	Tokens  []models.SCIMToken `json:"tokens"`
}

func (a *API) adminSCIMGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)

	tokens, err := models.FindActiveSCIMTokensBySSOProvider(a.db.WithContext(ctx), provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM tokens").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMStatusResponse{
		Enabled: provider.IsEnabled() && len(tokens) > 0,
		BaseURL: scim.BaseURL(a.config),
		Tokens:  tokens,
	})
}

func (a *API) adminSCIMDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)

	var tokens []models.SCIMToken
	if err := a.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var err error
		tokens, err = a.disableSCIM(tx, r, provider)
		return err
	}); err != nil {
		return apierrors.NewInternalServerError("Error disabling SCIM").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMStatusResponse{
		Enabled: false,
		BaseURL: scim.BaseURL(a.config),
		Tokens:  tokens,
	})
}

func (a *API) deprovisionSCIM(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) error {
	if _, err := a.disableSCIM(tx, r, provider); err != nil {
		return err
	}
	banned, err := models.BanDeprovisionedSCIMUsers(tx, provider.ID, a.Now().Add(scimProviderDeletedBan))
	if err != nil || banned == 0 {
		return err
	}
	return a.auditSCIM(tx, r, getAdminUser(r.Context()), models.SCIMUsersBannedAction, provider.ID, map[string]any{"banned_user_count": banned})
}

func (a *API) disableSCIM(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) ([]models.SCIMToken, error) {
	if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
		return nil, err
	}
	tokens, err := models.RevokeSCIMTokensBySSOProvider(tx, provider.ID)
	if err != nil || len(tokens) == 0 {
		return tokens, err
	}
	prefixes := make([]string, len(tokens))
	for i := range tokens {
		prefixes[i] = tokens[i].Prefix
	}
	return tokens, a.auditSCIM(tx, r, getAdminUser(r.Context()), models.SCIMDisabledAction, provider.ID, map[string]any{"token_prefixes": prefixes})
}

func (a *API) adminSCIMTokensCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	params := &AdminSCIMTokenCreateParams{}
	if body, err := utilities.GetBodyBytes(r); err != nil || len(body) > 0 {
		if err := retrieveRequestParams(r, params); err != nil {
			return err
		}
	}
	if params.ExpiresAt != nil && !params.ExpiresAt.After(a.Now()) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
	}

	var (
		token     *models.SCIMToken
		plaintext string
	)
	if err := db.Transaction(func(tx *storage.Connection) error {
		if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
			return err
		}
		active, err := models.FindActiveSCIMTokensBySSOProvider(tx, provider.ID)
		if err != nil {
			return err
		}
		if token, plaintext, err = models.CreateSCIMToken(tx, provider, params.ExpiresAt); err != nil {
			return err
		}
		if err := a.auditSCIM(tx, r, getAdminUser(ctx), models.SCIMTokenCreatedAction, provider.ID, map[string]any{"token_prefix": token.Prefix}); err != nil {
			return err
		}
		if len(active) > 0 || !provider.IsEnabled() {
			return nil
		}
		return a.auditSCIM(tx, r, getAdminUser(ctx), models.SCIMEnabledAction, provider.ID, map[string]any{"token_prefix": token.Prefix})
	}); err != nil {
		if errors.Is(err, models.SCIMTokenExpiryError{}) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
		}
		return apierrors.NewInternalServerError("Error creating SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusCreated, &AdminSCIMTokenCreateResponse{
		BaseURL:   scim.BaseURL(a.config),
		Token:     plaintext,
		SCIMToken: token,
	})
}

func (a *API) adminSCIMTokensList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)

	tokens, err := models.FindSCIMTokensBySSOProvider(a.db.WithContext(ctx), provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error listing SCIM tokens").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMTokenListResponse{Tokens: tokens})
}

func (a *API) adminSCIMTokensRevoke(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	var token *models.SCIMToken
	if err := db.Transaction(func(tx *storage.Connection) error {
		if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
			return err
		}
		var err error
		if token, err = models.FindSCIMTokenByPrefix(tx, provider.ID, chi.URLParam(r, "prefix")); err != nil {
			return err
		}
		if token.IsRevoked() {
			return nil
		}
		active, err := models.FindActiveSCIMTokensBySSOProvider(tx, provider.ID)
		if err != nil {
			return err
		}
		if err = token.Revoke(tx); err != nil {
			return err
		}
		if err := a.auditSCIM(tx, r, getAdminUser(ctx), models.SCIMTokenRevokedAction, provider.ID, map[string]any{"token_prefix": token.Prefix}); err != nil {
			return err
		}
		if len(active) != 1 || active[0].ID != token.ID {
			return nil
		}
		return a.auditSCIM(tx, r, getAdminUser(ctx), models.SCIMDisabledAction, provider.ID, map[string]any{"token_prefixes": []string{token.Prefix}})
	}); err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMTokenNotFound, "SCIM token not found")
		}
		return apierrors.NewInternalServerError("Error revoking SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, token)
}
