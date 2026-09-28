package scim

import (
	"encoding/json"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type users struct {
	location       string
	groupsLocation string
}

func NewUserRepository(config *conf.GlobalConfiguration, db *storage.Connection, provisioner UserProvisioner) server.Repository[*core.User] {
	return &repository[*core.User, UserInput, models.SCIMUser]{
		db:          db,
		provisioner: provisioner,
		schemas:     core.Schemas{core.NewSchema(core.SchemaUser).With(core.UserAttributes()...)},
		filter:      eqFilter{name: "userName"},
		find:        models.FindSCIMUser,
		findPage:    models.FindSCIMUsers,
		input:       toUserInput,
		render:      users{location: BaseURL(config) + "/Users/", groupsLocation: BaseURL(config) + "/Groups/"}.render,
	}
}

func (u users) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser) ([]*core.User, error) {
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
	}
	memberships, err := models.FindSCIMGroupsForUsers(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	groups := map[uuid.UUID][]core.GroupMembership{}
	for _, m := range memberships {
		groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
			Value:   m.GroupID.String(),
			Ref:     u.groupsLocation + m.GroupID.String(),
			Display: m.Display,
			Type:    "direct",
		})
	}

	result := make([]*core.User, 0, len(rows))
	for i := range rows {
		user, err := u.decode(&rows[i])
		if err != nil {
			return nil, err
		}
		user.Groups = groups[rows[i].ID]
		result = append(result, user)
	}
	return result, nil
}

func (u users) decode(row *models.SCIMUser) (*core.User, error) {
	user := &core.User{}
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, err
	}
	active := row.Active
	user.Active = &active
	user.ID = row.ID.String()
	user.Schemas = []core.SchemaURI{core.SchemaUser}
	if user.EnterpriseUser != nil {
		user.Schemas = append(user.Schemas, core.SchemaEnterpriseUser)
	}
	user.Meta = meta(resourceTypeUser, u.location+user.ID, row.CreatedAt, row.UpdatedAt)
	return user, nil
}
