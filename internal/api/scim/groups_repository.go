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

type groups struct {
	location      string
	usersLocation string
}

func NewGroupRepository(config *conf.GlobalConfiguration, db *storage.Connection, provisioner GroupProvisioner) server.Repository[*core.Group] {
	return &repository[*core.Group, GroupInput, models.SCIMGroup]{
		db:          db,
		provisioner: provisioner,
		schemas:     core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)},
		filter:      eqFilter{name: "displayName"},
		find:        models.FindSCIMGroup,
		findPage:    models.FindSCIMGroups,
		input:       toGroupInput,
		render:      groups{location: BaseURL(config) + "/Groups/", usersLocation: BaseURL(config) + "/Users/"}.render,
	}
}

func (g groups) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup) ([]*core.Group, error) {
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
	}
	memberships, err := models.FindSCIMGroupMembers(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	members := map[uuid.UUID][]core.Member{}
	for _, m := range memberships {
		members[m.GroupID] = append(members[m.GroupID], core.Member{
			Value: m.SCIMUserID.String(),
			Ref:   g.usersLocation + m.SCIMUserID.String(),
			Type:  resourceTypeUser,
		})
	}

	result := make([]*core.Group, 0, len(rows))
	for i := range rows {
		group, err := g.decode(&rows[i])
		if err != nil {
			return nil, err
		}
		group.Members = members[rows[i].ID]
		result = append(result, group)
	}
	return result, nil
}

func (g groups) decode(row *models.SCIMGroup) (*core.Group, error) {
	group := &core.Group{}
	if err := json.Unmarshal(row.Resource, group); err != nil {
		return nil, err
	}
	group.ID = row.ID.String()
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Meta = meta(resourceTypeGroup, g.location+group.ID, row.CreatedAt, row.UpdatedAt)
	return group, nil
}
