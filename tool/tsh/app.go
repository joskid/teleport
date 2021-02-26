/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"strings"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/gravitational/trace"
	"github.com/pborman/uuid"
)

// onAppLogin implements "tsh app login" command.
func onAppLogin(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	app, err := getRegisteredApp(cf, tc)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	sessionID, err := issueAppCert(cf, tc, app, profile)
	if err != nil {
		return trace.Wrap(err)
	}
	err = createAppSession(cf, tc, app, sessionID)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf(`Logged into app %q. Example curl command:

%v
`, app.Name, formatAppConfig(tc, profile, app.Name, app.PublicAddr, appFormatCURL))
	return nil
}

// getRegisteredApp returns the registered application with the specified name.
func getRegisteredApp(cf *CLIConf, tc *client.TeleportClient) (app *types.App, err error) {
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		allServers, err := tc.ListAppServers(cf.Context)
		for _, server := range allServers {
			for _, a := range server.GetApps() {
				if a.Name == cf.AppName {
					app = a
				}
			}
		}
		return trace.Wrap(err)
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if app == nil {
		return nil, trace.NotFound("app %q not found, use `tsh app ls` to see registered apps", cf.AppName)
	}
	return app, nil
}

// issueAppCert reissues user certificate with routing information for the
// specified app encoded into it.
func issueAppCert(cf *CLIConf, tc *client.TeleportClient, app *types.App, profile *client.ProfileStatus) (string, error) {
	sessionID := uuid.New()
	err := tc.ReissueUserCerts(cf.Context, client.ReissueParams{
		RouteToCluster: tc.SiteName,
		RouteToApp: proto.RouteToApp{
			Name:        app.Name,
			SessionID:   sessionID,
			PublicAddr:  app.PublicAddr,
			ClusterName: tc.SiteName,
		},
		AccessRequests: profile.ActiveRequests.AccessRequests,
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return sessionID, nil
}

// createAppSession creates a new application access web session for the
// specified application.
func createAppSession(cf *CLIConf, tc *client.TeleportClient, app *types.App, sessionID string) error {
	// key, err := tc.LocalAgent().GetKey(client.WithAppCerts(tc.SiteName, app.Name))
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	err := tc.CreateAppSession(cf.Context, types.CreateAppSessionRequest{
		Username:    tc.Username,
		PublicAddr:  app.PublicAddr,
		ClusterName: tc.SiteName,
		SessionID:   sessionID,
	})
	// err := tc.UpsertAppSession(cf.Context, types.NewWebSession(sessionID,
	// 	types.KindWebSession,
	// 	types.KindAppSession,
	// 	types.WebSessionSpecV2{
	// 		User: tc.Username,
	// 		//Priv:    key.Priv,
	// 		//Pub:     key.Pub,
	// 		//TLSCert: key.AppTLSCerts[app.Name],
	// 		// The app session TTL will be set on the backend to make sure
	// 		// it does not exceed TTL of the identity.
	// 	}))
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// onAppLogout implements "tsh app logout" command.
func onAppLogout(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	var logout []tlsca.RouteToApp
	// If app name wasn't given on the command line, log out of all.
	if cf.AppName == "" {
		logout = profile.Apps
	} else {
		for _, app := range profile.Apps {
			if app.Name == cf.AppName {
				logout = append(logout, app)
			}
		}
		if len(logout) == 0 {
			return trace.BadParameter("Not logged into app %q",
				cf.AppName)
		}
	}
	for _, app := range logout {
		err = tc.DeleteAppSession(cf.Context, app.SessionID)
		if err != nil && !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		err = tc.LogoutApp(app.Name)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	if len(logout) == 1 {
		fmt.Printf("Logged out of app %q\n", logout[0].Name)
	} else {
		fmt.Println("Logged out of all apps")
	}
	return nil
}

// onAppConfig implements "tsh app config" command.
func onAppConfig(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}
	app, err := pickActiveApp(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Print(formatAppConfig(tc, profile, app.Name, app.PublicAddr, cf.Format))
	return nil
}

func formatAppConfig(tc *client.TeleportClient, profile *client.ProfileStatus, appName, appPublicAddr, format string) string {
	switch format {
	case appFormatURI:
		return fmt.Sprintf("https://%v:%v", appPublicAddr, tc.WebProxyPort())
	case appFormatCA:
		return fmt.Sprintf("%v", profile.CACertPath())
	case appFormatCert:
		return fmt.Sprintf("%v", profile.AppCertPath(appName))
	case appFormatKey:
		return fmt.Sprintf("%v", profile.KeyPath())
	case appFormatCURL:
		return fmt.Sprintf(`curl \
  --cacert %v \
  --cert %v \
  --key %v \
  https://%v:%v`,
			profile.CACertPath(),
			profile.AppCertPath(appName),
			profile.KeyPath(),
			appPublicAddr,
			tc.WebProxyPort())
	}
	return fmt.Sprintf(`Name:      %v
URI:       https://%v:%v
CA:        %v
Cert:      %v
Key:       %v
`, appName, appPublicAddr, tc.WebProxyPort(), profile.CACertPath(),
		profile.AppCertPath(appName), profile.KeyPath())
}

// pickActiveApp returns the app the current profile is logged into.
//
// If logged into multiple apps, returns an error unless one was specified
// explicily on CLI.
func pickActiveApp(cf *CLIConf) (*tlsca.RouteToApp, error) {
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(profile.Apps) == 0 {
		return nil, trace.NotFound("Please login using 'tsh app login' first")
	}
	name := cf.AppName
	if name == "" {
		apps := profile.AppNames()
		if len(apps) > 1 {
			return nil, trace.BadParameter("Multiple apps are available (%v), please specify one via CLI argument",
				strings.Join(apps, ", "))
		}
		name = apps[0]
	}
	for _, app := range profile.Apps {
		if app.Name == name {
			return &app, nil
		}
	}
	return nil, trace.NotFound("Not logged into app %q", name)
}

const (
	// appFormatURI prints app URI.
	appFormatURI = "uri"
	// appFormatCA prints app CA cert path.
	appFormatCA = "ca"
	// appFormatCert prints app cert path.
	appFormatCert = "cert"
	// appFormatKey prints app key path.
	appFormatKey = "key"
	// appFormatCURL prints app curl command.
	appFormatCURL = "curl"
)
