package entra

import (
	"encoding/json"
	"errors"
	"github.com/h0useh3ad/HeadCode/pkg/utils"
	"net/url"
	"strings"

	"net/http"
)

type TenantInfo struct {
	Domain        string
	TenantId      string
	ExampleUpn    string
	UserRealmInfo *UserRealmInfo
	OidcInfo      *OidcInfo
}

type UserRealmInfo struct {
	NameSpaceType          string `json:"NameSpaceType"`
	Login                  string `json:"Login"`
	DomainName             string `json:"DomainName"`
	FederationBrandName    string `json:"FederationBrandName"`
	FederationProtocol     string `json:"federation_protocol"`
	FederatedAuthURL       string `json:"AuthURL"`
	parsedFederatedAuthURL *url.URL
}

type OidcInfo struct {
	Issuer string `json:"issuer"`
}

func GetTenantInfo(domain string) (*TenantInfo, error) {
	upn := utils.RandomUsername() + "@" + domain

	userRealmInfo, err := getUserRealmInfo(upn)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(domain, userRealmInfo.DomainName) {
		errMsg := "Specified Domain " + domain + " does not match with retrieved DomainName " + userRealmInfo.DomainName
		return nil, errors.New(errMsg)
	}

	oidcInfo, err := getOidcInfo(domain)
	if err != nil {
		return nil, err
	}

	issuerUrl, err := url.Parse(oidcInfo.Issuer)
	if err != nil {
		return nil, err
	}
	tenantId := strings.Replace(issuerUrl.Path, "/", "", -1)

	federatedAuthUrl, err := url.Parse(userRealmInfo.FederatedAuthURL)
	if err != nil {
		return nil, err
	}
	userRealmInfo.parsedFederatedAuthURL = federatedAuthUrl

	return &TenantInfo{
		Domain:        domain,
		TenantId:      tenantId,
		ExampleUpn:    upn,
		UserRealmInfo: userRealmInfo,
		OidcInfo:      oidcInfo,
	}, nil
}

func getUserRealmInfo(upn string) (*UserRealmInfo, error) {

	resp, err := http.Get("https://login.microsoftonline.com/common/userrealm/" + upn + "?api-version=2.1")

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := "Request failed with status code:" + resp.Status
		return nil, errors.New(errMsg)
	}

	var userRealmInfo UserRealmInfo
	err = json.NewDecoder(resp.Body).Decode(&userRealmInfo)

	if err != nil {
		return nil, err
	}

	return &userRealmInfo, nil
}

func getOidcInfo(domain string) (*OidcInfo, error) {
	resp, err := http.Get("https://login.microsoftonline.com/" + domain + "/.well-known/openid-configuration")

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := "Request failed with status code:" + resp.Status
		return nil, errors.New(errMsg)
	}

	var oidcInfo OidcInfo
	err = json.NewDecoder(resp.Body).Decode(&oidcInfo)

	if err != nil {
		return nil, err
	}

	return &oidcInfo, nil
}