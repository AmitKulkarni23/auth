package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofrs/uuid"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func groupWith(displayName, externalID string, memberIDs ...string) string {
	members := ""
	for i, id := range memberIDs {
		if i > 0 {
			members += ","
		}
		members += `{"value":"` + id + `"}`
	}
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + displayName + `","externalId":"` + externalID + `","members":[` + members + `]}`
}

func (ts *SCIMUsersTestSuite) createGroup(token, body string) string {
	w, created := ts.do(token, http.MethodPost, "/Groups", body)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	return created["id"].(string)
}

func (ts *SCIMUsersTestSuite) listGroups(token, filter string) map[string]any {
	w, body := ts.do(token, http.MethodGet, "/Groups?"+url.Values{"filter": {filter}}.Encode(), "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return body
}

func memberValues(group map[string]any) []string {
	values := []string{}
	members, _ := group["members"].([]any)
	for _, member := range members {
		values = append(values, member.(map[string]any)["value"].(string))
	}
	return values
}

func (ts *SCIMUsersTestSuite) TestGroupsLifecycle() {
	alice := ts.create(ts.TokenA, userWith("Alice@Example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))

	w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Engineering", "okta-g1", alice))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	location := "http://localhost:9999/scim/v2/Groups/" + id
	require.Equal(ts.T(), location, w.Header().Get("Location"))
	require.NotEmpty(ts.T(), w.Header().Get("ETag"))
	require.Equal(ts.T(), "Engineering", created["displayName"])
	require.Equal(ts.T(), "okta-g1", created["externalId"])
	meta := created["meta"].(map[string]any)
	require.Equal(ts.T(), "Group", meta["resourceType"])
	require.Equal(ts.T(), location, meta["location"])
	member := created["members"].([]any)[0].(map[string]any)
	require.Equal(ts.T(), alice, member["value"])
	require.Equal(ts.T(), "User", member["type"])
	require.NotContains(ts.T(), member, "display")
	require.Equal(ts.T(), "http://localhost:9999/scim/v2/Users/"+alice, member["$ref"])

	var stored models.SCIMGroup
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.Equal(ts.T(), ts.A.ID, stored.SSOProviderID)
	require.NotContains(ts.T(), string(stored.Resource), "members")
	require.NotContains(ts.T(), string(stored.Resource), `"id"`)

	for _, filter := range []string{`displayName eq "Engineering"`, `displayName eq "engineering"`, `externalId eq "okta-g1"`} {
		found := ts.listGroups(ts.TokenA, filter)
		require.EqualValues(ts.T(), 1, found["totalResults"], filter)
		require.Equal(ts.T(), id, found["Resources"].([]any)[0].(map[string]any)["id"], filter)
	}

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Groups/"+id, groupWith("Engineering", "okta-g1", bob))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{bob}, memberValues(replaced))
	require.Equal(ts.T(), meta["created"], replaced["meta"].(map[string]any)["created"])

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"members","value":[{"value":"`+alice+`"}]},
		{"op":"replace","path":"displayName","value":"Platform"}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.ElementsMatch(ts.T(), []string{alice, bob}, memberValues(patched))
	require.Equal(ts.T(), "Platform", patched["displayName"])

	w, patched = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members[value eq \"`+bob+`\"]"}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{alice}, memberValues(patched))

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), "Platform", got["displayName"])
	require.Equal(ts.T(), []string{alice}, memberValues(got))

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	w, _ = ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusNotFound, w.Code)

	w, _ = ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *SCIMUsersTestSuite) TestGroupsWithoutMembers() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Empty"}`)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(ts.T(), created, "members")

	ts.createGroup(ts.TokenA, groupWith("Empty", "e-2"))
	require.EqualValues(ts.T(), 2, ts.listGroups(ts.TokenA, `displayName eq "Empty"`)["totalResults"])
}

func (ts *SCIMUsersTestSuite) TestGroupsRejectInvalidMembers() {
	outsider := ts.create(ts.TokenB, userWith("mallory@example.com", "m-1"))
	deleted := ts.create(ts.TokenA, userWith("gone@example.com", "g-1"))
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+deleted, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	existing := ts.createGroup(ts.TokenA, groupWith("Existing", ""))
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	for name, body := range map[string]string{
		"other provider": groupWith("Engineering", "", outsider),
		"deleted user":   groupWith("Engineering", "", deleted),
		"unknown id":     groupWith("Engineering", "", "00000000-0000-0000-0000-000000000000"),
		"not a uuid":     groupWith("Engineering", "", "alice"),
		"nested group":   `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[{"value":"00000000-0000-0000-0000-000000000000","type":"Group"}]}`,
	} {
		w, body := ts.do(ts.TokenA, http.MethodPost, "/Groups", body)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, name+" "+w.Body.String())
		require.Equal(ts.T(), "invalidValue", body["scimType"], name)
	}
	w, _ = ts.do(ts.TokenA, http.MethodPut, "/Groups/"+existing, groupWith("Existing", "", outsider))
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.EqualValues(ts.T(), 1, ts.listGroups(ts.TokenA, "")["totalResults"])
	for _, entry := range hook.AllEntries() {
		require.NotEqual(ts.T(), "audit_event", entry.Message, entry.Data)
	}
}

func (ts *SCIMUsersTestSuite) TestPatchRejectsRemoveWithValue() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", alice, bob))

	for path, body := range map[string]string{
		"/Groups/" + id:   `{"op":"Remove","path":"members","value":[{"$ref":null,"value":"` + bob + `"}]}`,
		"/Users/" + alice: `{"op":"remove","path":"emails","value":[{"value":"alice@example.com"}]}`,
	} {
		w, got := ts.do(ts.TokenA, http.MethodPatch, path, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`+body+`]}`)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, path+" "+w.Body.String())
		require.Equal(ts.T(), "invalidSyntax", got["scimType"], path)
	}

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.ElementsMatch(ts.T(), []string{alice, bob}, memberValues(got))
	w, got = ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.NotEmpty(ts.T(), got["emails"])

	w, got = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members[value eq \"`+bob+`\"]","value":null}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{alice}, memberValues(got))
}

func (ts *SCIMUsersTestSuite) TestGroupsExternalIDUniqueWithinProvider() {
	ts.createGroup(ts.TokenA, groupWith("A", "g-1"))

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("B", "g-1"))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])

	ts.createGroup(ts.TokenB, groupWith("A", "g-1"))
}

func (ts *SCIMUsersTestSuite) TestGroupsETagAndIfMatch() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Engineering", "g-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	stale := w.Header().Get("ETag")

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Platform"}]}`
	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPatch, "/Groups/"+id, patch, "If-Match", stale)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	current := w.Header().Get("ETag")
	require.NotEqual(ts.T(), stale, current)

	for _, tc := range []struct{ method, body string }{
		{http.MethodPut, groupWith("Engineering", "g-1")},
		{http.MethodPatch, patch},
		{http.MethodDelete, ""},
	} {
		w, _ := ts.doAs(protocol.MediaType, ts.TokenA, tc.method, "/Groups/"+id, tc.body, "If-Match", stale)
		require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, tc.method+" "+w.Body.String())
	}

	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodDelete, "/Groups/"+id, "", "If-Match", current)
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
}

func (ts *SCIMUsersTestSuite) TestGroupsRemoveDeletedMembers() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	eng := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice, bob))
	ops := ts.createGroup(ts.TokenA, groupWith("Ops", "g-2", alice))
	before := len(ts.scimAuditEntries())

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+eng, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), []string{bob}, memberValues(got))
	w, got = ts.do(ts.TokenA, http.MethodGet, "/Groups/"+ops, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Empty(ts.T(), memberValues(got))

	count, err := ts.API.db.Q().Where("scim_user_id = ?", alice).Count(&models.SCIMGroupMember{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)

	removed := []string{}
	for _, entry := range ts.scimAuditEntries()[before:] {
		if entry.Payload["action"] != string(models.SCIMGroupMemberRemovedAction) {
			continue
		}
		traits := entry.Payload["traits"].(map[string]any)
		require.Equal(ts.T(), alice, traits["scim_user_id"])
		removed = append(removed, traits["scim_group_id"].(string))
	}
	require.ElementsMatch(ts.T(), []string{eng, ops}, removed)
}

func (ts *SCIMUsersTestSuite) TestGroupsVersionChangesWhenMemberDeleted() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))
	w, _ := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
	stale := w.Header().Get("ETag")

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	w, _ = ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
	require.NotEqual(ts.T(), stale, w.Header().Get("ETag"))
	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, "/Groups/"+id, groupWith("Engineering", "g-1"), "If-Match", stale)
	require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, w.Body.String())
}

func (ts *SCIMUsersTestSuite) TestUserDeleteWaitsForGroupWrite() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice, bob))
	group, err := models.FindSCIMGroup(ts.API.db, ts.A.ID, uuid.FromStringOrNil(id))
	require.NoError(ts.T(), err)

	code, err := ts.whileLocked(
		func(tx *storage.Connection) error {
			_, err := models.FindSCIMGroupForUpdate(tx, ts.A.ID, group.ID)
			return err
		},
		func(tx *storage.Connection) error {
			_, _, err := models.ReplaceSCIMGroupMembers(tx, group, []uuid.UUID{uuid.FromStringOrNil(bob)})
			return err
		},
		http.MethodDelete, "/Users/"+alice, "",
	)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), http.StatusNoContent, code)

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), []string{bob}, memberValues(got))
}

func (ts *SCIMUsersTestSuite) TestGroupsKeepDeactivatedMembers() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))
	before := len(ts.scimAuditEntries())

	w, _ := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+alice, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"active","value":false}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	w, got := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"members","value":[{"value":"`+bob+`"}]}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.ElementsMatch(ts.T(), []string{alice, bob}, memberValues(got))

	w, user := ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, user["active"])
	require.Len(ts.T(), user["groups"], 1)

	for _, entry := range ts.scimAuditEntries()[before:] {
		require.NotEqual(ts.T(), string(models.SCIMGroupMemberRemovedAction), entry.Payload["action"])
	}
}

func (ts *SCIMUsersTestSuite) TestGroupsSortAndPaginate() {
	ts.createGroup(ts.TokenA, groupWith("beta", "g-2"))
	ts.createGroup(ts.TokenA, groupWith("Alpha", "g-1"))
	ts.createGroup(ts.TokenA, groupWith("gamma", "g-3"))

	w, page := ts.do(ts.TokenA, http.MethodGet, "/Groups?sortBy=displayName&startIndex=2&count=1", "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.EqualValues(ts.T(), 3, page["totalResults"])
	require.Equal(ts.T(), "beta", page["Resources"].([]any)[0].(map[string]any)["displayName"])

	w, page = ts.do(ts.TokenA, http.MethodGet, "/Groups?sortBy=displayName&sortOrder=descending", "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "gamma", page["Resources"].([]any)[0].(map[string]any)["displayName"])

	w, body := ts.do(ts.TokenA, http.MethodGet, "/Groups?sortBy=members.value", "")
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
}

func (ts *SCIMUsersTestSuite) TestGroupsUnsupportedFilters() {
	for _, filter := range []string{
		`displayName co "eng"`,
		`members.value eq "00000000-0000-0000-0000-000000000000"`,
		`members[value eq "00000000-0000-0000-0000-000000000000"]`,
		`displayName eq "a" or displayName eq "b"`,
		`displayName pr`,
	} {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Groups?"+url.Values{"filter": {filter}}.Encode(), "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, filter)
		require.Equal(ts.T(), "invalidFilter", body["scimType"], filter)
	}
}

func (ts *SCIMUsersTestSuite) TestGroupsUnknownID() {
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		w, _ := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+id, "")
		require.Equal(ts.T(), http.StatusNotFound, w.Code, id)
	}
}

func (ts *SCIMUsersTestSuite) TestUsersGroupsAttribute() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	ops := ts.createGroup(ts.TokenA, groupWith("Ops", "g-2", alice))
	eng := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))

	groupsOf := func(user map[string]any) []map[string]any {
		found := []map[string]any{}
		groups, _ := user["groups"].([]any)
		for _, group := range groups {
			found = append(found, group.(map[string]any))
		}
		return found
	}
	storedResource := func(id string) string {
		var stored models.SCIMUser
		require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
		return string(stored.Resource)
	}

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []map[string]any{
		{"value": eng, "$ref": "http://localhost:9999/scim/v2/Groups/" + eng, "display": "Engineering", "type": "direct"},
		{"value": ops, "$ref": "http://localhost:9999/scim/v2/Groups/" + ops, "display": "Ops", "type": "direct"},
	}, groupsOf(got))

	w, got = ts.do(ts.TokenA, http.MethodGet, "/Users/"+bob, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), got, "groups")

	listed := ts.list(ts.TokenA, `userName eq "alice@example.com"`)
	require.Len(ts.T(), groupsOf(listed["Resources"].([]any)[0].(map[string]any)), 2)

	claimed := `[{"value":"` + ops + `","display":"Forged"}]`
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"carol@example.com","emails":[{"primary":true,"value":"carol@example.com"}],"groups":`+claimed+`}`)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(ts.T(), created, "groups")
	require.NotContains(ts.T(), storedResource(created["id"].(string)), "groups")

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+bob, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@example.com","groups":`+claimed+`}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), replaced, "groups")
	require.NotContains(ts.T(), storedResource(bob), "groups")

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+alice, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"displayName","value":"Alice"}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), groupsOf(patched), 2)
	require.NotContains(ts.T(), storedResource(alice), "groups")

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+ops, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	w, got = ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), groupsOf(got), 1)
	require.Equal(ts.T(), eng, groupsOf(got)[0]["value"])
}

func (ts *SCIMUsersTestSuite) TestGroupsAuditLog() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	before := len(ts.scimAuditEntries())

	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))

	w, _ := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Engineering", "g-1"))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	w, _ = ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Invalid", "g-2", uuid.Must(uuid.NewV4()).String()))
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())

	w, _ = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"members","value":[{"value":"`+bob+`"}]},
		{"op":"remove","path":"members[value eq \"`+alice+`\"]"},
		{"op":"replace","path":"displayName","value":"Platform"}
	]}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())

	tokens, err := models.FindSCIMTokensBySSOProvider(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)

	type event struct {
		action, displayName, scimUserID string
	}
	events := []event{}
	for _, entry := range ts.scimAuditEntries()[before:] {
		require.Equal(ts.T(), uuid.Nil.String(), entry.Payload["actor_id"])
		require.Equal(ts.T(), "scim:"+tokens[0].Prefix, entry.Payload["actor_username"])
		traits := entry.Payload["traits"].(map[string]any)
		require.Equal(ts.T(), ts.A.ID.String(), traits["sso_provider_id"])
		require.Equal(ts.T(), id, traits["scim_group_id"])
		require.Equal(ts.T(), "success", traits["outcome"])
		displayName, _ := traits["display_name"].(string)
		scimUserID, _ := traits["scim_user_id"].(string)
		events = append(events, event{entry.Payload["action"].(string), displayName, scimUserID})
	}
	require.ElementsMatch(ts.T(), []event{
		{string(models.SCIMGroupCreatedAction), "Engineering", ""},
		{string(models.SCIMGroupMemberAddedAction), "", alice},
		{string(models.SCIMGroupUpdatedAction), "Platform", ""},
		{string(models.SCIMGroupMemberAddedAction), "", bob},
		{string(models.SCIMGroupMemberRemovedAction), "", alice},
		{string(models.SCIMGroupMemberRemovedAction), "", bob},
		{string(models.SCIMGroupDeletedAction), "Platform", ""},
	}, events)
}

func (ts *SCIMUsersTestSuite) TestGroupsOktaPushReplay() {
	const (
		oktaAlice = "24fd0f10-d02e-45f6-8f33-53e2393f0a7c"
		oktaBob   = "870e2e05-0e57-4f77-af74-3306be7aac3a"
		oktaGroup = "abb1dcbc-7b00-41c7-8b9d-78e4b826e572"
	)
	alice := ts.create(ts.TokenA, userWith("alice.capture@example.com", "00u184ow24y3MJ1Do698"))
	bob := ts.create(ts.TokenA, userWith("bob.capture@example.com", "00u184ouv4hrBmc86698"))

	raw, err := os.ReadFile("testdata/scim/okta_group_push.json")
	require.NoError(ts.T(), err)
	var steps []struct {
		Step     string `json:"step"`
		Requests []struct {
			Method string          `json:"method"`
			Path   string          `json:"path"`
			Body   json.RawMessage `json:"body"`
		} `json:"requests"`
	}
	require.NoError(ts.T(), json.Unmarshal([]byte(strings.NewReplacer(oktaAlice, alice, oktaBob, bob).Replace(string(raw))), &steps))

	type state struct {
		displayName string
		members     []string
		aliceActive bool
	}
	expected := map[string]state{
		"push group":                        {"scim-capture", []string{}, true},
		"add alice (sent twice)":            {"scim-capture", []string{alice}, true},
		"retry: alice and bob":              {"scim-capture", []string{alice, bob}, true},
		"remove alice":                      {"scim-capture", []string{bob}, true},
		"remove bob":                        {"scim-capture", []string{}, true},
		"rename":                            {"scim-capture-renamed", []string{}, true},
		"re-add alice (sent twice)":         {"scim-capture-renamed", []string{alice}, true},
		"deactivate alice":                  {"scim-capture-renamed", []string{alice}, false},
		"reactivate alice and reassign app": {"scim-capture-renamed", []string{alice}, true},
	}
	require.Len(ts.T(), steps, len(expected))

	group := ""
	for _, step := range steps {
		want, ok := expected[step.Step]
		require.True(ts.T(), ok, step.Step)
		for _, request := range step.Requests {
			path := strings.TrimPrefix(request.Path, "/scim/v2")
			body := string(request.Body)
			if group != "" {
				path = strings.ReplaceAll(path, oktaGroup, group)
				body = strings.ReplaceAll(body, oktaGroup, group)
			}
			w, got := ts.do(ts.TokenA, request.Method, path, body)
			require.Less(ts.T(), w.Code, 300, "%s: %s %s: %s", step.Step, request.Method, path, w.Body.String())
			if group == "" {
				group = got["id"].(string)
			}
		}

		w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+group, "")
		require.Equal(ts.T(), http.StatusOK, w.Code, step.Step)
		require.Equal(ts.T(), want.displayName, got["displayName"], step.Step)
		require.ElementsMatch(ts.T(), want.members, memberValues(got), step.Step)
		w, user := ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
		require.Equal(ts.T(), http.StatusOK, w.Code, step.Step)
		require.Equal(ts.T(), want.aliceActive, user["active"], step.Step)
	}
}
