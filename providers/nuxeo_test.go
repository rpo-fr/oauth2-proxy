package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const (
	nuxeoAccessToken  = "eyJNuxeo.eyJAccess.Token"
	nuxeoUserinfoPath = "/nuxeo/api/v1/me"
)

func testNuxeoProvider(backend *httptest.Server) (*NuxeoProvider, error) {
	p := NewNuxeoProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		options.NuxeoOptions{})

	if backend != nil {
		bURL, err := url.Parse(backend.URL)
		if err != nil {
			return nil, err
		}
		hostname := bURL.Host

		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}

	return p, nil
}

var _ = Describe("Nuxeo Provider Tests", func() {
	Context("New Provider Init", func() {
		It("uses defaults", func() {
			providerData := NewNuxeoProvider(&ProviderData{}, options.NuxeoOptions{}).Data()
			Expect(providerData.ProviderName).To(Equal("Nuxeo"))
			Expect(providerData.LoginURL.String()).To(Equal("https://nuxeo.org/nuxeo/oauth2/authorize"))
			Expect(providerData.RedeemURL.String()).To(Equal("https://nuxeo.org/nuxeo/oauth2/token"))
			Expect(providerData.ProfileURL.String()).To(Equal(""))
			Expect(providerData.ValidateURL.String()).To(Equal("https://nuxeo.org/nuxeo/api/v1/me"))
			Expect(providerData.Scope).To(Equal("api"))
		})

		It("overrides defaults", func() {
			p := NewNuxeoProvider(
				&ProviderData{
					LoginURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/nuxeo/oauth2/authorize"},
					RedeemURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/nuxeo/oauth2/token"},
					ProfileURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/nuxeo/api/v1/me"},
					ValidateURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/nuxeo/api/v1/me"},
					Scope: "profile"},
				options.NuxeoOptions{})
			providerData := p.Data()

			Expect(providerData.ProviderName).To(Equal("Nuxeo"))
			Expect(providerData.LoginURL.String()).To(Equal("https://example.com/nuxeo/oauth2/authorize"))
			Expect(providerData.RedeemURL.String()).To(Equal("https://example.com/nuxeo/oauth2/token"))
			Expect(providerData.ProfileURL.String()).To(Equal("https://example.com/nuxeo/api/v1/me"))
			Expect(providerData.ValidateURL.String()).To(Equal("https://example.com/nuxeo/api/v1/me"))
			Expect(providerData.Scope).To(Equal("profile"))
		})
	})

	Context("EnrichSession", func() {
		type enrichSessionTableInput struct {
			backendHandler http.HandlerFunc
			expectedError  error
			expectedEmail  string
			expectedGroups []string
		}

		DescribeTable("should return expected results",
			func(in enrichSessionTableInput) {
				backend := httptest.NewServer(in.backendHandler)
				p, err := testNuxeoProvider(backend)
				Expect(err).To(BeNil())

				p.ProfileURL, err = url.Parse(
					fmt.Sprintf("%s%s", backend.URL, nuxeoUserinfoPath),
				)
				Expect(err).To(BeNil())

				session := &sessions.SessionState{AccessToken: nuxeoAccessToken}
				err = p.EnrichSession(context.Background(), session)

				if in.expectedError != nil {
					Expect(err).To(Equal(in.expectedError))
				} else {
					Expect(err).To(BeNil())
				}

				Expect(session.Email).To(Equal(in.expectedEmail))

				if in.expectedGroups != nil {
					Expect(session.Groups).To(Equal(in.expectedGroups))
				} else {
					Expect(session.Groups).To(BeNil())
				}
			},
			Entry("email and multiple groups", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"email": "michael.bland@gsa.gov",
							"groups": [
								"test-grp1",
								"test-grp2"
							]
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: []string{"test-grp1", "test-grp2"},
			}),
			Entry("email and single group", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"email": "michael.bland@gsa.gov",
							"groups": ["test-grp1"]
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: []string{"test-grp1"},
			}),
			Entry("email and no groups", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"email": "michael.bland@gsa.gov"
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: nil,
			}),
			Entry("missing email", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(200)
					_, err := w.Write([]byte(`
						{
							"groups": [
								"test-grp1",
								"test-grp2"
							]
						}
					`))
					if err != nil {
						panic(err)
					}
				},
				expectedError: errors.New(
					"unable to extract email from userinfo endpoint: type assertion to string failed"),
				expectedEmail:  "",
				expectedGroups: []string{"test-grp1", "test-grp2"},
			}),
			Entry("request failure", enrichSessionTableInput{
				backendHandler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(500)
				},
				expectedError:  errors.New(`unexpected status "500": `),
				expectedEmail:  "",
				expectedGroups: nil,
			}),
		)
	})
})
