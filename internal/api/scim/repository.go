package scim

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	resourceTypeUser  = "User"
	resourceTypeGroup = "Group"
)

var errMissingSSOProvider = errors.New("scim: request has no SSO provider")

type repository[T core.Resource, I, R any] struct {
	db          *storage.Connection
	provisioner Provisioner[I, R]
	schemas     core.Schemas
	filter      eqFilter
	find        func(tx *storage.Connection, providerID, id uuid.UUID) (*R, error)
	findPage    func(tx *storage.Connection, providerID uuid.UUID, query models.SCIMQuery) ([]R, int, error)
	input       func(item T) (I, error)
	render      func(tx *storage.Connection, providerID uuid.UUID, rows []R) ([]T, error)
}

type eqFilter struct {
	name string
}

func (r *repository[T, I, R]) List(ctx context.Context, query *protocol.SearchRequest) ([]T, int, error) {
	providerID, err := providerFrom(ctx)
	if err != nil {
		return nil, 0, err
	}
	criteria := models.SCIMFilter{}
	if query.Filter != "" {
		if criteria, err = protocol.Filter(r.schemas, query.Filter, r.filter); err != nil {
			return nil, 0, err
		}
	}
	order, err := r.order(query)
	if err != nil {
		return nil, 0, err
	}

	db := r.db.WithContext(ctx)
	rows, total, err := r.findPage(db, providerID, models.SCIMQuery{Filter: criteria, Order: order, Offset: query.Offset(), Limit: query.Count})
	if err != nil {
		return nil, 0, err
	}
	items, err := r.render(db, providerID, rows)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *repository[T, I, R]) Get(ctx context.Context, id string) (T, error) {
	var zero T
	providerID, resourceID, _, err := target(ctx, id, "")
	if err != nil {
		return zero, err
	}
	db := r.db.WithContext(ctx)
	row, err := r.find(db, providerID, resourceID)
	if err != nil {
		return zero, translate(err)
	}
	return r.renderOne(db, providerID, row)
}

func (r *repository[T, I, R]) Create(ctx context.Context, item T) (T, error) {
	var zero T
	providerID, err := providerFrom(ctx)
	if err != nil {
		return zero, err
	}
	input, err := r.input(item)
	if err != nil {
		return zero, err
	}
	row, err := r.provisioner.Create(ctx, providerID, input)
	if err != nil {
		return zero, translate(err)
	}
	return r.renderOne(r.db.WithContext(ctx), providerID, row)
}

func (r *repository[T, I, R]) Replace(ctx context.Context, item T) (T, error) {
	var zero T
	common := item.Common()
	providerID, resourceID, updatedAt, err := target(ctx, common.ID, common.Meta.Version)
	if err != nil {
		return zero, err
	}
	input, err := r.input(item)
	if err != nil {
		return zero, err
	}
	row, err := r.provisioner.Replace(ctx, providerID, resourceID, input, updatedAt)
	if err != nil {
		return zero, translate(err)
	}
	return r.renderOne(r.db.WithContext(ctx), providerID, row)
}

func (r *repository[T, I, R]) Delete(ctx context.Context, id, version string) error {
	providerID, resourceID, updatedAt, err := target(ctx, id, version)
	if err != nil {
		return err
	}
	return translate(r.provisioner.Delete(ctx, providerID, resourceID, updatedAt))
}

func (r *repository[T, I, R]) order(query *protocol.SearchRequest) (models.SCIMOrder, error) {
	if query.SortBy == "" {
		return models.SCIMOrder{}, nil
	}
	parent, attribute, err := query.SortAttribute(r.schemas)
	if err != nil {
		return models.SCIMOrder{}, err
	}
	key := parent.Name
	if attribute != parent {
		key += "." + attribute.Name
	}
	order := models.SCIMOrder{Descending: query.Descending()}
	switch strings.ToLower(key) {
	case "id":
		order.By = models.SCIMSortByID
	case strings.ToLower(r.filter.name):
		order.By = models.SCIMSortByName
	case "meta.created":
		order.By = models.SCIMSortByCreatedAt
	case "meta.lastmodified":
		order.By = models.SCIMSortByUpdatedAt
	default:
		return models.SCIMOrder{}, scimerrors.ErrInvalidValue(fmt.Sprintf(`"sortBy" must be one of "id", %q, "meta.created" or "meta.lastModified"`, r.filter.name))
	}
	return order, nil
}

func (r *repository[T, I, R]) renderOne(db *storage.Connection, providerID uuid.UUID, row *R) (T, error) {
	items, err := r.render(db, providerID, []R{*row})
	if err != nil {
		var zero T
		return zero, err
	}
	return items[0], nil
}

func (f eqFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
	text, ok := value.(string)
	if op != filter.OpEquals || attribute.Parent != nil || !ok {
		return f.unsupported()
	}
	switch attribute.Definition.Name {
	case f.name:
		return models.SCIMFilter{Name: &text}, nil
	case "externalId":
		return models.SCIMFilter{ExternalID: &text}, nil
	}
	return f.unsupported()
}

func (f eqFilter) Present(*protocol.Attribute) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f eqFilter) And(models.SCIMFilter, models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f eqFilter) Or(models.SCIMFilter, models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f eqFilter) Not(models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f eqFilter) ValuePath(*protocol.Attribute, func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f eqFilter) unsupported() (models.SCIMFilter, error) {
	return models.SCIMFilter{}, scimerrors.ErrInvalidFilter(fmt.Sprintf(`only "%s eq" and "externalId eq" filters are supported`, f.name))
}

func target(ctx context.Context, id, version string) (providerID, resourceID uuid.UUID, updatedAt *time.Time, err error) {
	if providerID, err = providerFrom(ctx); err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	if resourceID, err = uuid.FromString(id); err != nil {
		return uuid.Nil, uuid.Nil, nil, errNotFound()
	}
	if updatedAt, err = parseVersion(version); err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	return providerID, resourceID, updatedAt, nil
}

func providerFrom(ctx context.Context) (uuid.UUID, error) {
	providerID, ok := SSOProviderID(ctx)
	if !ok || providerID == uuid.Nil {
		return uuid.Nil, errMissingSSOProvider
	}
	return providerID, nil
}

func meta(resourceType core.ResourceTypeName, location string, created, updated time.Time) core.Meta {
	return core.Meta{
		ResourceType: resourceType,
		Created:      created.UTC(),
		LastModified: updated.UTC(),
		Location:     location,
		Version:      version(updated),
	}
}

func version(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

func parseVersion(version string) (*time.Time, error) {
	if version == "" {
		return nil, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return nil, errStale()
	}
	updatedAt := time.UnixMicro(micros)
	return &updatedAt, nil
}

func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case models.IsNotFoundError(err):
		return errNotFound()
	case errors.Is(err, models.SCIMUserStaleError{}), errors.Is(err, models.SCIMGroupStaleError{}):
		return errStale()
	case errors.Is(err, models.SCIMGroupConflictError{}):
		return scimerrors.ErrUniqueness(`"externalId" must be unique`)
	case errors.As(err, &models.SCIMGroupMemberNotFoundError{}):
		return errMemberNotFound()
	case errors.Is(err, models.SCIMUserConflictError{}):
		return scimerrors.ErrUniqueness(`"userName" and "externalId" must be unique`)
	case errors.Is(err, models.SCIMUserLinkedError{}):
		return scimerrors.ErrUniqueness("user is already provisioned by this provider")
	}
	return err
}

func errNotFound() error {
	return scimerrors.ErrNotFound("Resource not found")
}

func errStale() error {
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func errMemberNotFound() error {
	return scimerrors.ErrInvalidValue(`"members.value" must reference a User in this provider`)
}
