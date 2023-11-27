package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type NuxeoProvider struct {
	*ProviderData
}

var _ Provider = (*NuxeoProvider)(nil)

const (
	nuxeoProviderName = "Nuxeo"
	nuxeoDefaultScope = "api"
)

var (
	// Default Login URL for Nuxeo.
	// Pre-parsed URL of https://nuxeo.org/oauth/authorize.
	nuxeoDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "nuxeo.org",
		Path:   "/nuxeo/oauth2/authorize",
	}

	// Default Redeem URL for Nuxeo.
	// Pre-parsed URL of ttps://nuxeo.org/oauth/token.
	nuxeoDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "nuxeo.org",
		Path:   "/nuxeo/oauth2/token",
	}

	// Default Validation URL for Nuxeo.
	// Pre-parsed URL of https://nuxeo.org/nuxeo/api/v1/me.
	nuxeoDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "nuxeo.org",
		Path:   "/nuxeo/api/v1/me",
	}
)

// NewNuxeoProvider creates a KeyCloakProvider using the passed ProviderData
func NewNuxeoProvider(p *ProviderData, opts options.NuxeoOptions) *NuxeoProvider {
	p.setProviderDefaults(providerDefaults{
		name:        nuxeoProviderName,
		loginURL:    nuxeoDefaultLoginURL,
		redeemURL:   nuxeoDefaultRedeemURL,
		profileURL:  nil,
		validateURL: nuxeoDefaultValidateURL,
		scope:       nuxeoDefaultScope,
	})

	provider := &NuxeoProvider{ProviderData: p}
	// provider.setAllowedGroups(opts.Groups)
	return provider
}

// EnrichSession uses the Nuxeo userinfo endpoint to populate the session's
// email and groups.
func (p *NuxeoProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	// groups, err := json.Get("groups").StringArray()
	// if err == nil {
	// 	for _, group := range groups {
	// 		if group != "" {
	// 			s.Groups = append(s.Groups, group)
	// 		}
	// 	}
	// }

	email, err := json.Get("properties").Get("email").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	preferredUsername, err := json.Get("id").String()
	if err == nil {
		s.PreferredUsername = preferredUsername
	}

	user, err := json.Get("id").String()
	if err == nil {
		s.User = user
	}

	if s.User == "" && s.PreferredUsername != "" {
		s.User = s.PreferredUsername
	}

	return nil
}

// ValidateSession validates the AccessToken
func (p *NuxeoProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
