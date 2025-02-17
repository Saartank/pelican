//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package web_ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	tempPasswdFile *os.File
	router         *gin.Engine
)

func setupTestAuthDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := path.Join(tmpDir, "authdb")
	_, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	passFile, err := htpasswd.New(dbPath, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	require.NoError(t, err)

	authDB.Store(passFile)
}

func cleanupAuthDB() {
	authDB.Store(nil)
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	defer func() {
		if err := egrp.Wait(); err != nil {
			fmt.Println("Failure when shutting down service:", err)
			os.Exit(1)
		}
	}()
	defer cancel()

	//set a temporary password file:
	tempFile, err := os.CreateTemp("", "web-ui-passwd")
	if err != nil {
		fmt.Println("Failed to setup web-ui-passwd file")
		os.Exit(1)
	}
	tempPasswdFile = tempFile
	//Override viper default for testing
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())

	//Make a testing issuer.jwk file to get a cookie
	tempJWKDir, err := os.MkdirTemp("", "tempDir")
	if err != nil {
		fmt.Println("Error making temp jwk dir")
		os.Exit(1)
	}

	//Override viper default for testing
	viper.Set(param.IssuerKeysDirectory.GetName(), filepath.Join(tempJWKDir, "issuer-keys"))

	// Ensure we load up the default configs.
	dirname, err := os.MkdirTemp("", "tmpDir")
	if err != nil {
		fmt.Println("Error making temp config dir")
		os.Exit(1)
	}
	viper.Set("ConfigDir", dirname)
	config.InitConfig()
	viper.Set("Server.UILoginRateLimit", 100)

	if err := config.InitServer(ctx, server_structs.OriginType); err != nil {
		fmt.Println("Failed to configure the test module")
		os.Exit(1)
	}

	//Get keys
	_, err = config.GetIssuerPublicJWKS()
	if err != nil {
		fmt.Println("Error issuing jwks")
		os.Exit(1)
	}
	router = gin.Default()

	//Configure Web API
	err = ConfigureServerWebAPI(ctx, router, egrp)
	if err != nil {
		fmt.Println("Error configuring web UI")
		os.Exit(1)
	}
	//Run the tests
	exitCode := m.Run()

	//Clean up created files by removing them and exit
	os.Remove(tempPasswdFile.Name())
	os.RemoveAll(tempJWKDir)
	os.Exit(exitCode)
}

func TestHandleWebUIAuth(t *testing.T) {
	route := gin.New()
	route.GET("/view/*requestPath", handleWebUIAuth, func(ctx *gin.Context) { ctx.Status(200) })

	t.Run("redirect-to-init-without-db", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/initialization/code/", r.Result().Header.Get("Location"))
	})

	t.Run("init-page-no-redirct-without-db", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/initialization/code/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/initialization/password/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)
	})

	t.Run("no-redirect-without-db-on-init-page", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/initialization/code/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)
	})

	t.Run("no-redirect-to-login-with-db-initialized", func(t *testing.T) {
		// We let the frontend to handle unauthorized user (if the password is initialized)
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages, so we will pass the admin check and return 200
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages, so we will pass the admin check and return 200
		req, err = http.NewRequest("GET", "/view/registry/origin", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		r = httptest.NewRecorder()
		// This route **is** in ui.go/adminAccessPages,
		// but the user is not logged in, so we will hand it over to the frontend for the redirect
		req, err = http.NewRequest("GET", "/view/origin", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		authDB.Store(nil)
	})

	t.Run("403-for-logged-in-non-admin-user", func(t *testing.T) {
		server_utils.ResetTestState()
		// We let the frontend to handle unauthorized user (if the password is initialized)
		setupTestAuthDB(t)
		t.Cleanup(func() {
			cleanupAuthDB()
			server_utils.ResetTestState()
		})

		tmpDir := t.TempDir()
		issuerDirectory := filepath.Join(tmpDir, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), issuerDirectory)
		viper.Set(param.Server_ExternalWebUrl.GetName(), "https://example.com")

		_, err := config.GetIssuerPrivateJWK()
		require.NoError(t, err)

		tk := token.NewWLCGToken()
		tk.Issuer = "https://example.com"
		tk.Subject = "regular-user"
		tk.Lifetime = 5 * time.Minute
		tk.AddAudiences("https://example.com")
		tk.AddScopes(token_scopes.WebUi_Access)
		tok, err := tk.CreateToken()
		require.NoError(t, err)

		r := httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages
		req, err = http.NewRequest("GET", "/view/registry/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		// This route **is** in ui.go/adminAccessPages, and the user is not logged in, so we return 403
		req, err = http.NewRequest("GET", "/view/origin", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusForbidden, r.Result().StatusCode)

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/cache/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusForbidden, r.Result().StatusCode)

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/config/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusForbidden, r.Result().StatusCode)

		authDB.Store(nil)
	})

	t.Run("init-page-redirect-to-root-with-db-initialized", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/initialization/code/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/", r.Result().Header.Get("Location"))

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/initialization/password/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/", r.Result().Header.Get("Location"))

		authDB.Store(nil)
	})

	t.Run("skip-check-on-non-html-file", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.js", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})

	t.Run("pass-check-on-director", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/director/index.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})

	t.Run("pass-check-on-registry", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/registry/index.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})
}

func TestMapPrometheusPath(t *testing.T) {
	t.Run("aggregate-frontend-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/view/_next/static/123.js", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/view/_next/:resource", get)
	})

	t.Run("aggregate-healthtest-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/healthTest/pelican/self-test-monitoring-123-456.txt", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/healthTest/:testfile", get)
	})

	t.Run("aggregate-two-level-origin-redirect-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar/barz", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/object/foo/bar/:path", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/object/foo/bar.txt", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar/level3/level4/file.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/object/foo/bar/:path", get)
	})

	t.Run("aggregate-two-level-object-redirect-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar/barz", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/origin/foo/bar/:path", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/origin/foo/bar.txt", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar/level3/level4/file.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/origin/foo/bar/:path", get)
	})
}

func TestServerHostRestart(t *testing.T) {
	route := gin.New()
	route.POST("/api/v1.0/restart", AuthHandler, AdminAuthHandler, hotRestartServer)
	viper.Set("IssuerKey", filepath.Join(t.TempDir(), "issuer.jwk"))

	t.Run("unauthorized-no-token", func(t *testing.T) {
		r := httptest.NewRecorder()
		req, err := http.NewRequest("POST", "/api/v1.0/restart", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusUnauthorized, r.Result().StatusCode)
	})

	t.Run("forbidden-non-admin-user", func(t *testing.T) {
		// Create token for regular user
		tk := token.NewWLCGToken()
		tk.Issuer = "https://example.com"
		tk.Subject = "regular-user"
		tk.Lifetime = 5 * time.Minute
		tk.AddAudiences("https://example.com")
		tk.AddScopes(token_scopes.WebUi_Access)
		tok, err := tk.CreateToken()
		require.NoError(t, err)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("POST", "/api/v1.0/restart", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusForbidden, r.Result().StatusCode)
	})

	t.Run("success-admin-user", func(t *testing.T) {
		// Create a buffered channel for restart flag
		config.RestartFlag = make(chan any, 1)
		// Create token for admin user
		tk := token.NewWLCGToken()
		tk.Issuer = "https://example.com"
		tk.Subject = "admin-user"
		tk.Lifetime = 5 * time.Minute
		tk.AddAudiences("https://example.com")
		tk.AddScopes(token_scopes.WebUi_Access)
		tok, err := tk.CreateToken()
		require.NoError(t, err)

		r := httptest.NewRecorder()
		viper.Set("Server.UIAdminUsers", []string{"admin1", "admin2"})
		c := gin.CreateTestContextOnly(r, route)
		c.Set("User", "admin1")
		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/restart", nil)
		c.Request = req
		require.NoError(t, err)
		c.Request.AddCookie(&http.Cookie{Name: "login", Value: tok})

		// Create a done channel to signal when the handler completes
		done := make(chan struct{})
		// Start another goroutine to handle the restart flag
		// Handler goroutine: Sends data to channel config.RestartFlag
		// Main test goroutine: Receives data from channel config.RestartFlag
		// This prevents deadlock because both the sender and receiver are
		// running concurrently instead of sequentially
		go func() {
			defer close(done)
			// Call the handler directly with the context
			hotRestartServer(c)
		}()

		// Wait for either the handler to complete or context to timeout
		select {
		case <-done:
			// Handler completed (the done channel is closed)
		case <-c.Done():
			t.Fatal("Handler timed out")
			return
		}

		// Check response status and body
		assert.Equal(t, http.StatusOK, r.Result().StatusCode)
		var resp server_structs.SimpleApiResp
		err = json.NewDecoder(r.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RespOK, resp.Status)
		assert.Equal(t, "Server hot restart initiated", resp.Msg)

		// Verify that the restart flag was sent
		select {
		case flag := <-config.RestartFlag:
			assert.Equal(t, true, flag)
		case <-c.Done():
			t.Fatal("Context timeout while waiting for restart flag")
		case <-time.After(time.Second):
			t.Fatal("Timeout waiting for restart flag")
		}
	})
}
