/*
Copyright 2015-2021 Gravitational, Inc.

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

package auth

import (
	"context"
	"testing"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/stretchr/testify/require"
)

// TestSetAuthPreference tests the dynamic configuration rules described
// in rfd/0016-dynamic-configuration.md § Implementation.
func TestSetAuthPreference(t *testing.T) {
	testAuth, err := NewTestAuthServer(TestAuthServerConfig{Dir: t.TempDir()})
	require.NoError(t, err)

	// Initialize with the default auth preference.
	err = testAuth.AuthServer.SetAuthPreference(types.DefaultAuthPreference())
	require.NoError(t, err)
	storedAuthPref, err := testAuth.AuthServer.GetAuthPreference()
	require.NoError(t, err)
	require.Empty(t, ResourceDiff(storedAuthPref, types.DefaultAuthPreference()))

	// Grant VerbRead and VerbUpdate privileges for cluster_auth_preference.
	allowRules := []types.Rule{
		{
			Resources: []string{"cluster_auth_preference"},
			Verbs:     []string{types.VerbRead, types.VerbUpdate},
		},
	}
	server := withAllowRules(t, testAuth, allowRules)

	dynamicAuthPref, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		SecondFactor: constants.SecondFactorOff,
	})
	require.NoError(t, err)
	t.Run("from default to dynamic", func(t *testing.T) {
		err = server.SetAuthPreference(dynamicAuthPref)
		require.NoError(t, err)
		storedAuthPref, err = server.GetAuthPreference()
		require.NoError(t, err)
		require.Empty(t, ResourceDiff(storedAuthPref, dynamicAuthPref))
	})

	newDynamicAuthPref, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		SecondFactor: constants.SecondFactorOTP,
	})
	require.NoError(t, err)
	t.Run("from dynamic to another dynamic", func(t *testing.T) {
		err = server.SetAuthPreference(newDynamicAuthPref)
		require.NoError(t, err)
		storedAuthPref, err = server.GetAuthPreference()
		require.NoError(t, err)
		require.Empty(t, ResourceDiff(storedAuthPref, newDynamicAuthPref))
	})

	staticAuthPref := newU2FAuthPreferenceFromConfigFile(t)
	t.Run("from dynamic to static", func(t *testing.T) {
		err = server.SetAuthPreference(staticAuthPref)
		require.NoError(t, err)
		storedAuthPref, err = server.GetAuthPreference()
		require.NoError(t, err)
		require.Empty(t, ResourceDiff(storedAuthPref, staticAuthPref))
	})

	newAuthPref, err := types.NewAuthPreferenceFromConfigFile(types.AuthPreferenceSpecV2{
		SecondFactor: constants.SecondFactorOTP,
	})
	require.NoError(t, err)
	replaceStatic := func(success bool) func(t *testing.T) {
		return func(t *testing.T) {
			err = server.SetAuthPreference(newAuthPref)
			checkSetResult := require.Error
			if success {
				checkSetResult = require.NoError
			}
			checkSetResult(t, err)

			storedAuthPref, err = server.GetAuthPreference()
			require.NoError(t, err)
			expectedStored := staticAuthPref
			if success {
				expectedStored = newAuthPref
			}
			require.Empty(t, ResourceDiff(storedAuthPref, expectedStored))
		}
	}

	t.Run("replacing static fails without VerbCreate privilege", replaceStatic(false))

	// Grant VerbCreate privilege for cluster_auth_preference.
	allowRules[0].Verbs = append(allowRules[0].Verbs, types.VerbCreate)
	server = withAllowRules(t, testAuth, allowRules)

	t.Run("replacing static success with VerbCreate privilege", replaceStatic(true))
}

func withAllowRules(t *testing.T, srv *TestAuthServer, allowRules []types.Rule) *ServerWithRoles {
	username := "some-user"
	_, role, err := CreateUserAndRoleWithoutRoles(srv.AuthServer, username, nil)
	require.NoError(t, err)
	role.SetRules(types.Allow, allowRules)
	err = srv.AuthServer.UpsertRole(context.TODO(), role)
	require.NoError(t, err)

	localUser := LocalUser{Username: username, Identity: tlsca.Identity{Username: username}}
	authContext, err := contextForLocalUser(localUser, srv.AuthServer.Identity, srv.AuthServer.Access)
	require.NoError(t, err)

	return &ServerWithRoles{
		authServer: srv.AuthServer,
		sessions:   srv.SessionServer,
		alog:       srv.AuditLog,
		context:    *authContext,
	}
}
