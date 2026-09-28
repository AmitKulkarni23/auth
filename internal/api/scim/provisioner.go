package scim

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
)

type UserInput struct {
	Resource []byte
	UserName string
	Email    string
}

type GroupInput struct {
	Resource []byte
	Members  []uuid.UUID
}

type Provisioner[I, R any] interface {
	Create(ctx context.Context, providerID uuid.UUID, input I) (*R, error)
	Replace(ctx context.Context, providerID, id uuid.UUID, input I, updatedAt *time.Time) (*R, error)
	Delete(ctx context.Context, providerID, id uuid.UUID, updatedAt *time.Time) error
}

type (
	UserProvisioner  = Provisioner[UserInput, models.SCIMUser]
	GroupProvisioner = Provisioner[GroupInput, models.SCIMGroup]
)

func toUserInput(user *core.User) (UserInput, error) {
	resource, err := encodeResource(user, "id", "meta", "password", "groups")
	if err != nil {
		return UserInput{}, err
	}
	return UserInput{
		Resource: resource,
		UserName: user.UserName,
		Email:    primaryEmail(user.Emails),
	}, nil
}

func toGroupInput(group *core.Group) (GroupInput, error) {
	members, err := memberIDs(group.Members)
	if err != nil {
		return GroupInput{}, err
	}
	resource, err := encodeResource(group, "id", "meta", "members")
	if err != nil {
		return GroupInput{}, err
	}
	return GroupInput{Resource: resource, Members: members}, nil
}

func encodeResource(resource core.Resource, drop ...string) ([]byte, error) {
	encoded, err := json.Marshal(resource) // #nosec G117
	if err != nil {
		return nil, err
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	for _, key := range drop {
		delete(fields, key)
	}
	return json.Marshal(fields)
}

func memberIDs(members []core.Member) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		if member.Type != "" && member.Type != resourceTypeUser {
			return nil, scimerrors.ErrInvalidValue(`nested groups are not supported; "members.type" must be "User"`)
		}
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, errMemberNotFound()
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func primaryEmail(emails []core.Email) string {
	for _, email := range emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}
