package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
)

func (ts *SCIMUsersTestSuite) okta(method, path, body string, headers ...string) (int, map[string]any) {
	contentType := "application/scim+json; charset=utf-8"
	if method == http.MethodPost {
		contentType = "application/json"
	}
	headers = append([]string{"Accept", "application/scim+json", "Accept-Charset", "utf-8", "User-Agent", "OKTA SCIM Integration"}, headers...)
	w, got := ts.doAs(contentType, ts.TokenA, method, path, body, headers...)
	return w.Code, got
}

func oktaFilter(userName string) string {
	return "/Users?" + url.Values{"filter": {`userName eq "` + userName + `"`}}.Encode()
}

func (ts *SCIMUsersTestSuite) TestOktaSpec() {
	const (
		userName   = "okta.spec.user@example.com"
		givenName  = "Okta"
		familyName = "Spec"
	)
	create := func(email string) string {
		return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","name":{"givenName":"` + givenName + `","familyName":"` + familyName + `"},"emails":[{"primary":true,"value":"` + email + `","type":"work"}],"displayName":"` + givenName + " " + familyName + `","active":true}`
	}
	requireError := func(got map[string]any, status string) {
		require.NotEmpty(ts.T(), got["detail"])
		require.Equal(ts.T(), status, got["status"])
		require.Contains(ts.T(), got["schemas"], string(protocol.SchemaError))
	}
	ts.create(ts.TokenA, oktaUser)

	status, got := ts.okta(http.MethodGet, "/Users?count=1&startIndex=1", "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.Contains(ts.T(), got["schemas"], string(protocol.SchemaListResponse))
	require.IsType(ts.T(), float64(0), got["itemsPerPage"])
	require.IsType(ts.T(), float64(0), got["startIndex"])
	require.IsType(ts.T(), float64(0), got["totalResults"])
	require.NotEmpty(ts.T(), got["Resources"])
	first := got["Resources"].([]any)[0].(map[string]any)
	require.NotEmpty(ts.T(), first["id"])
	require.NotEmpty(ts.T(), first["name"].(map[string]any)["familyName"])
	require.NotEmpty(ts.T(), first["name"].(map[string]any)["givenName"])
	require.NotEmpty(ts.T(), first["userName"])
	require.NotNil(ts.T(), first["active"])
	require.NotEmpty(ts.T(), first["emails"].([]any)[0].(map[string]any)["value"])
	id := first["id"].(string)

	status, got = ts.okta(http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.Equal(ts.T(), id, got["id"])
	require.NotEmpty(ts.T(), got["name"].(map[string]any)["familyName"])
	require.NotEmpty(ts.T(), got["name"].(map[string]any)["givenName"])
	require.NotEmpty(ts.T(), got["userName"])
	require.NotNil(ts.T(), got["active"])
	require.NotEmpty(ts.T(), got["emails"].([]any)[0].(map[string]any)["value"])

	for _, missing := range []string{"invalid.user@example.com", userName} {
		status, got = ts.okta(http.MethodGet, oktaFilter(missing), "")
		require.Equal(ts.T(), http.StatusOK, status, missing)
		require.Contains(ts.T(), got["schemas"], string(protocol.SchemaListResponse), missing)
		require.EqualValues(ts.T(), 0, got["totalResults"], missing)
	}

	status, got = ts.okta(http.MethodGet, "/Users/010101", "")
	require.Equal(ts.T(), http.StatusNotFound, status)
	requireError(got, "404")

	status, got = ts.okta(http.MethodPost, "/Users", create(userName))
	require.Equal(ts.T(), http.StatusCreated, status)
	require.Equal(ts.T(), true, got["active"])
	require.NotEmpty(ts.T(), got["id"])
	require.Equal(ts.T(), familyName, got["name"].(map[string]any)["familyName"])
	require.Equal(ts.T(), givenName, got["name"].(map[string]any)["givenName"])
	require.Contains(ts.T(), got["schemas"], string(core.SchemaUser))
	require.Equal(ts.T(), userName, got["userName"])
	created := got["id"].(string)

	status, got = ts.okta(http.MethodGet, "/Users/"+created, "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.Equal(ts.T(), userName, got["userName"])
	require.Equal(ts.T(), familyName, got["name"].(map[string]any)["familyName"])
	require.Equal(ts.T(), givenName, got["name"].(map[string]any)["givenName"])

	status, _ = ts.okta(http.MethodPost, "/Users", create(userName))
	require.Equal(ts.T(), http.StatusConflict, status)

	status, got = ts.okta(http.MethodGet, oktaFilter(strings.ToUpper(userName)), "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.EqualValues(ts.T(), 1, got["totalResults"])
	require.Equal(ts.T(), created, got["Resources"].([]any)[0].(map[string]any)["id"])

	status, got = ts.okta(http.MethodGet, "/Groups", "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.EqualValues(ts.T(), 0, got["totalResults"])

	status, got = ts.okta(http.MethodGet, oktaFilter(strings.ToUpper(userName)), "", "Authorization", "non-token")
	require.Equal(ts.T(), http.StatusUnauthorized, status)
	requireError(got, "401")

	status, got = ts.okta(http.MethodGet, "/Users/00919288221112222", "")
	require.Equal(ts.T(), http.StatusNotFound, status)
	requireError(got, "404")
}

func (ts *SCIMUsersTestSuite) TestOktaUserLifecycleReplay() {
	const (
		oktaID   = "da3f2ea4-03ec-49e4-ad50-f0806b15bda5"
		password = "okta-generated-password"
	)
	raw, err := os.ReadFile("testdata/scim/okta_user_lifecycle.json")
	require.NoError(ts.T(), err)
	var steps []struct {
		Step     string `json:"step"`
		Requests []struct {
			Method string          `json:"method"`
			Path   string          `json:"path"`
			Body   json.RawMessage `json:"body"`
		} `json:"requests"`
	}
	require.NoError(ts.T(), json.Unmarshal(raw, &steps))

	type state struct {
		familyName string
		active     bool
		found      int
	}
	expected := map[string]state{
		"assign new user":           {"Lifecycle", true, 0},
		"edit last name":            {"Lifecycle2", true, -1},
		"unassign":                  {"Lifecycle2", false, -1},
		"reassign (PUT sent twice)": {"Lifecycle2", true, 1},
	}
	require.Len(ts.T(), steps, len(expected))
	before := len(ts.scimAuditEntries())

	id, version := "", ""
	for _, step := range steps {
		want, ok := expected[step.Step]
		require.True(ts.T(), ok, step.Step)
		for _, request := range step.Requests {
			path := strings.TrimPrefix(request.Path, "/scim/v2")
			body := string(request.Body)
			if id != "" {
				path = strings.ReplaceAll(path, oktaID, id)
				body = strings.ReplaceAll(body, oktaID, id)
			}
			status, got := ts.okta(request.Method, path, body)
			require.Less(ts.T(), status, 300, "%s: %s %s", step.Step, request.Method, path)
			if strings.Contains(path, "filter=") {
				require.EqualValues(ts.T(), want.found, got["totalResults"], step.Step)
				if want.found > 0 {
					require.Equal(ts.T(), id, got["Resources"].([]any)[0].(map[string]any)["id"], step.Step)
				}
			}
			if request.Method == http.MethodPost {
				require.Contains(ts.T(), body, password)
				require.NotContains(ts.T(), got, "password")
				id = got["id"].(string)
			}
		}

		status, got := ts.okta(http.MethodGet, "/Users/"+id, "")
		require.Equal(ts.T(), http.StatusOK, status, step.Step)
		require.Equal(ts.T(), want.familyName, got["name"].(map[string]any)["familyName"], step.Step)
		require.Equal(ts.T(), want.active, got["active"], step.Step)
		current := got["meta"].(map[string]any)["version"].(string)
		require.NotEqual(ts.T(), version, current, step.Step)
		version = current

		count, err := ts.API.db.Q().Where("sso_provider_id = ?", ts.A.ID).Count(&models.SCIMUser{})
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), 1, count, step.Step)
	}

	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.NotContains(ts.T(), string(stored.Resource), "password")
	user, err := models.FindUserByID(ts.API.db, *stored.UserID)
	require.NoError(ts.T(), err)
	require.False(ts.T(), user.HasPassword())

	actions := []string{}
	for _, entry := range ts.scimAuditEntries()[before:] {
		payload, err := json.Marshal(entry.Payload)
		require.NoError(ts.T(), err)
		require.NotContains(ts.T(), string(payload), password)
		actions = append(actions, entry.Payload["action"].(string))
	}
	require.Equal(ts.T(), []string{
		string(models.SCIMUserCreatedAction),
		string(models.SCIMUserUpdatedAction),
		string(models.SCIMUserDeactivatedAction),
		string(models.SCIMUserReactivatedAction),
		string(models.SCIMUserUpdatedAction),
	}, actions)
}
