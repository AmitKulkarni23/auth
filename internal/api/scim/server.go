package scim

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
)

const BasePath = "/scim/v2"

type Server struct {
	server *server.Server
}

type Options struct {
	Validate server.TokenValidator
	Limit    func(http.Handler) http.Handler
	Users    server.Repository[*core.User]
	Groups   server.Repository[*core.Group]
}

func NewServer(config *conf.GlobalConfiguration, opts Options) *Server {
	requireToken := server.RequireBearerToken(opts.Validate)
	authenticate := func(next http.Handler) http.Handler {
		next = rejectRemoveWithValue(next)
		if opts.Limit != nil {
			next = opts.Limit(next)
		}
		return requireToken(next)
	}

	serviceProviderConfig := core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning()

	srv := server.New(BasePath, serviceProviderConfig,
		server.ErrorHandler(logError),
		server.WithResource(server.NewResource[*core.User](resourceTypeUser, "/Users", core.SchemaUser, core.UserAttributes()...).
			WithExtension(core.SchemaEnterpriseUser, core.EnterpriseUserAttributes()...).
			WithRepository(opts.Users)),
		server.WithResource(server.NewResource[*core.Group](resourceTypeGroup, "/Groups", core.SchemaGroup, core.GroupAttributes()...).
			WithRepository(opts.Groups)),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate),
	)
	serviceProviderConfig.Meta.Location = BaseURL(config) + "/ServiceProviderConfig"

	return &Server{server: srv}
}

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.server.ServeHTTP(w, r)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, scimerrors.ErrNotFound("Endpoint or resource does not exist"))
}

func (srv *Server) TooManyRequests(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached"))
}

func logError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
}

// RFC 7644 Section 3.5.2.2 defines no "value" for "remove"; refuse it rather than remove every value at "path".
func rejectRemoveWithValue(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			next.ServeHTTP(w, r)
			return
		}
		var read bytes.Buffer
		req, err := protocol.DecodePatchRequest(io.TeeReader(r.Body, &read))
		if err != nil {
			_ = protocol.SendError(w, err)
			return
		}
		for _, op := range req.Operations {
			if strings.EqualFold(string(op.Op), "remove") && len(op.Value) > 0 && string(bytes.TrimSpace(op.Value)) != "null" {
				_ = protocol.SendError(w, scimerrors.ErrInvalidSyntax(`"remove" does not take a "value"`))
				return
			}
		}
		r.Body = io.NopCloser(io.MultiReader(&read, r.Body))
		next.ServeHTTP(w, r)
	})
}
