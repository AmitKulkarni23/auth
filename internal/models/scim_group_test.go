package models

import (
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type SCIMGroupTestSuite struct {
	suite.Suite
	db       *storage.Connection
	provider *SSOProvider
}

func TestSCIMGroup(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &SCIMGroupTestSuite{db: conn}
	defer ts.db.Close()
	suite.Run(t, ts)
}

func (ts *SCIMGroupTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.provider = ts.createProvider()
}

func (ts *SCIMGroupTestSuite) createProvider() *SSOProvider {
	return createSCIMTestProvider(ts.T(), ts.db)
}

func (ts *SCIMGroupTestSuite) createGroup(providerID uuid.UUID, displayName string) *SCIMGroup {
	group, err := CreateSCIMGroup(ts.db, providerID, []byte(fmt.Sprintf(`{"displayName":%q}`, displayName)))
	require.NoError(ts.T(), err)
	return group
}

func (ts *SCIMGroupTestSuite) createUser(providerID uuid.UUID, userName string) *SCIMUser {
	user, err := CreateSCIMUser(ts.db, providerID, []byte(fmt.Sprintf(`{"userName":%q}`, userName)))
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMGroupTestSuite) TestCreate() {
	group, err := CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"Engineering","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), ts.provider.ID, group.SSOProviderID)
	require.Equal(ts.T(), "engineering", group.DisplayName)
	require.Equal(ts.T(), "ext-1", *group.ExternalID)
	require.JSONEq(ts.T(), `{"displayName":"Engineering","externalId":"ext-1"}`, string(group.Resource))
	require.False(ts.T(), group.CreatedAt.IsZero())
}

func (ts *SCIMGroupTestSuite) TestCreateAllowsDuplicateDisplayName() {
	ts.createGroup(ts.provider.ID, "Engineering")
	ts.createGroup(ts.provider.ID, "engineering")
}

func (ts *SCIMGroupTestSuite) TestCreateRejectsDuplicateExternalID() {
	_, err := CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"A","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)

	_, err = CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"B","externalId":"ext-1"}`))
	require.ErrorIs(ts.T(), err, SCIMGroupConflictError{})

	other := ts.createProvider()
	_, err = CreateSCIMGroup(ts.db, other.ID, []byte(`{"displayName":"C","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)
}

func (ts *SCIMGroupTestSuite) TestFindIsScopedToProvider() {
	group := ts.createGroup(ts.provider.ID, "Engineering")

	found, err := FindSCIMGroup(ts.db, ts.provider.ID, group.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), group.ID, found.ID)

	other := ts.createProvider()
	_, err = FindSCIMGroup(ts.db, other.ID, group.ID)
	require.ErrorIs(ts.T(), err, SCIMGroupNotFoundError{})
	require.True(ts.T(), IsNotFoundError(err))
}

func (ts *SCIMGroupTestSuite) TestFindGroupsFiltersAndSorts() {
	ts.createGroup(ts.provider.ID, "Beta")
	ts.createGroup(ts.provider.ID, "alpha")
	ts.createGroup(ts.createProvider().ID, "Alpha")

	displayName := "ALPHA"
	groups, total, err := FindSCIMGroups(ts.db, ts.provider.ID, SCIMQuery{Filter: SCIMFilter{Name: &displayName}, Limit: 10})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 1, total)
	require.Equal(ts.T(), "alpha", groups[0].DisplayName)

	groups, total, err = FindSCIMGroups(ts.db, ts.provider.ID, SCIMQuery{Order: SCIMOrder{By: SCIMSortByName, Descending: true}, Limit: 10})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 2, total)
	require.Equal(ts.T(), "beta", groups[0].DisplayName)
	require.Equal(ts.T(), "alpha", groups[1].DisplayName)

	groups, total, err = FindSCIMGroups(ts.db, ts.provider.ID, SCIMQuery{})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 2, total)
	require.Empty(ts.T(), groups)
}

func (ts *SCIMGroupTestSuite) TestReplaceChecksVersion() {
	group := ts.createGroup(ts.provider.ID, "Engineering")

	replaced, err := ReplaceSCIMGroup(ts.db, ts.provider.ID, group.ID, []byte(`{"displayName":"Platform"}`), &group.UpdatedAt)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "platform", replaced.DisplayName)

	_, err = ReplaceSCIMGroup(ts.db, ts.provider.ID, group.ID, []byte(`{"displayName":"Stale"}`), &group.UpdatedAt)
	require.ErrorIs(ts.T(), err, SCIMGroupStaleError{})

	_, err = ReplaceSCIMGroup(ts.db, ts.createProvider().ID, group.ID, []byte(`{"displayName":"Other"}`), nil)
	require.ErrorIs(ts.T(), err, SCIMGroupNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestDeleteRemovesMembers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	user := ts.createUser(ts.provider.ID, "alice")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{user.ID})
	require.NoError(ts.T(), err)

	_, err = DeleteSCIMGroup(ts.db, ts.provider.ID, group.ID, nil)
	require.NoError(ts.T(), err)

	_, err = FindSCIMGroup(ts.db, ts.provider.ID, group.ID)
	require.ErrorIs(ts.T(), err, SCIMGroupNotFoundError{})
	count, err := ts.db.Q().Where("group_id = ?", group.ID).Count(&SCIMGroupMember{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)

	_, err = DeleteSCIMGroup(ts.db, ts.provider.ID, group.ID, nil)
	require.ErrorIs(ts.T(), err, SCIMGroupNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersDiffs() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "Alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	carol := ts.createUser(ts.provider.ID, "carol")

	added, removed, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID, alice.ID})
	require.NoError(ts.T(), err)
	require.ElementsMatch(ts.T(), []uuid.UUID{alice.ID, bob.ID}, added)
	require.Empty(ts.T(), removed)

	added, removed, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{bob.ID, carol.ID})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []uuid.UUID{carol.ID}, added)
	require.Equal(ts.T(), []uuid.UUID{alice.ID}, removed)

	members, err := FindSCIMGroupMembers(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), members, 2)
	displays := []string{members[0].Display, members[1].Display}
	require.ElementsMatch(ts.T(), []string{"bob", "carol"}, displays)

	added, removed, err = ReplaceSCIMGroupMembers(ts.db, group, nil)
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), added)
	require.ElementsMatch(ts.T(), []uuid.UUID{bob.ID, carol.ID}, removed)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersRejectsOtherProviderUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	outsider := ts.createUser(ts.createProvider().ID, "mallory")

	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, outsider.ID})
	require.Equal(ts.T(), SCIMGroupMemberNotFoundError{IDs: []uuid.UUID{outsider.ID}}, err)

	members, err := FindSCIMGroupMembers(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), members)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersRejectsDeletedUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	_, err := DeleteSCIMUser(ts.db, ts.provider.ID, alice.ID, nil)
	require.NoError(ts.T(), err)

	_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID})
	require.Equal(ts.T(), SCIMGroupMemberNotFoundError{IDs: []uuid.UUID{alice.ID}}, err)

	_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{uuid.Must(uuid.NewV4())})
	require.ErrorAs(ts.T(), err, &SCIMGroupMemberNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestFindMembersHidesDeletedUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)

	_, err = DeleteSCIMUser(ts.db, ts.provider.ID, alice.ID, nil)
	require.NoError(ts.T(), err)

	members, err := FindSCIMGroupMembers(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), members)
}

func (ts *SCIMGroupTestSuite) TestFindGroupsForUsers() {
	engineering := ts.createGroup(ts.provider.ID, "Engineering")
	admins := ts.createGroup(ts.provider.ID, "Admins")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, engineering, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	_, _, err = ReplaceSCIMGroupMembers(ts.db, admins, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)

	groups, err := FindSCIMGroupsForUsers(ts.db, ts.provider.ID, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), groups, 3)

	byUser := map[uuid.UUID][]string{}
	for _, g := range groups {
		byUser[g.SCIMUserID] = append(byUser[g.SCIMUserID], g.Display)
	}
	require.Equal(ts.T(), []string{"Admins", "Engineering"}, byUser[alice.ID])
	require.Equal(ts.T(), []string{"Engineering"}, byUser[bob.ID])

	groups, err = FindSCIMGroupsForUsers(ts.db, ts.createProvider().ID, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), groups)
}
