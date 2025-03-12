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

package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (

	// Struct handling the cache's response to the origin's reversal
	// callback.
	reversalCallbackResponse struct {
		Certificate string `json:"certificate"`
	}

	// Represents a connection we may want to hijack.  The default transport
	// will create these connections and we'll later reverse them
	hijackConn struct {
		*net.TCPConn
		realConn *net.TCPConn
	}

	// A listener that reverses an existing, connected TCP socket.  One can
	// call 'accept' once (which will immediately return the provided TCP
	// socket); subsequent Accept calls will return net.ErrClosed.
	oneShotListener struct {
		conn atomic.Pointer[net.TCPConn]
		addr net.Addr
	}

	// Struct holding pending requests waiting on an origin callback
	pendingReversals struct {
		channel chan http.ResponseWriter
		prefix  string
	}
)

var (
	responseMapLock sync.Mutex                  = sync.Mutex{}
	response        map[string]pendingReversals = make(map[string]pendingReversals)
)

const requestIdBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

func (hj *hijackConn) Close() error {
	return nil
}

// Returns a new 'one shot listener' from a given TCP connection
func newOneShotListener(conn *net.TCPConn) net.Listener {
	listener := &oneShotListener{addr: conn.LocalAddr()}
	listener.conn.Store(conn)
	return listener
}

func (listener *oneShotListener) Accept() (conn net.Conn, err error) {
	tcpConn := listener.conn.Swap(nil)
	if tcpConn == nil {
		err = net.ErrClosed
		return
	}
	conn = tcpConn
	return
}

func (listener *oneShotListener) Close() error {
	listener.conn.Swap(nil)
	return nil
}

func (listener *oneShotListener) Addr() net.Addr {
	return listener.addr
}

func generatePrivateKey() (keyContents string, priv *ecdsa.PrivateKey, err error) {

	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}

	keyContents = base64.StdEncoding.EncodeToString(bytes)
	return
}

// Given a base64-encoded private key (output from generatePrivateKey),
// construct a private key object
func privateKeyFromBytes(keyContents string) (pkey crypto.PrivateKey, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyContents)
	if err != nil {
		return
	}

	pkey, err = x509.ParsePKCS8PrivateKey(keyBytes)
	return
}

func generateRequestId() string {
	reqIdB := make([]byte, 10)
	for idx := range reqIdB {
		reqIdB[idx] = requestIdBytes[mrand.Intn(len(requestIdBytes))]
	}
	return string(reqIdB)
}

// Given an origin's broker URL, return a connected socket to the origin
func ConnectToOrigin(ctx context.Context, brokerUrl, prefix, originName string) (conn net.Conn, err error) {

	// Ensure we have a local CA for signing an origin host certificate.
	if err = config.GenerateCACert(); err != nil {
		return
	}
	caCert, err := config.LoadCertificate(param.Server_TLSCACertificateFile.GetString())
	if err != nil {
		return
	}
	caPrivateKey, err := config.LoadPrivateKey(param.Server_TLSCAKey.GetString(), true)
	if err != nil {
		return
	}

	keyContents, privKey, err := generatePrivateKey()
	if err != nil {
		return
	}

	reqC := reversalRequest{
		RequestId:   generateRequestId(),
		PrivateKey:  keyContents,
		CallbackUrl: param.Server_ExternalWebUrl.GetString() + "/api/v1.0/broker/callback",
		OriginName:  originName,
		Prefix:      prefix,
	}
	reqBytes, err := json.Marshal(&reqC)
	if err != nil {
		return
	}

	reqReader := strings.NewReader(string(reqBytes))

	responseChannel := make(chan http.ResponseWriter)
	defer close(responseChannel)
	responseMapLock.Lock()
	response[reqC.RequestId] = pendingReversals{channel: responseChannel, prefix: prefix}
	responseMapLock.Unlock()
	defer func() {
		responseMapLock.Lock()
		defer responseMapLock.Unlock()
		delete(response, reqC.RequestId)
	}()

	// Send a request to the broker for a connection reversal
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerUrl, reqReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-cache/"+config.GetVersion())
	req.Header.Set("X-Pelican-Timeout", "10m")

	brokerAud, err := url.Parse(brokerUrl)
	if err != nil {
		err = errors.Wrap(err, "failure when constructing the broker audience URL")
		return
	}
	brokerAud.RawQuery = ""
	brokerAud.Path = ""

	cachePrefix := server_structs.GetCacheNS(param.Server_Hostname.GetString())
	token, err := createToken(cachePrefix, param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Reverse)
	if err != nil {
		err = errors.Wrap(err, "failure when constructing the broker request token")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Create a cloned transport which disables HTTP/2 (as that TCP string can't
	// be hijacked which we will need to do below).  The clone ensures that we're
	// not going to be reusing TCP connections.
	tr := config.GetTransport().Clone()
	tr.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrap(err, "Failure when invoking the broker URL")
		return
	}
	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "Failure when reading response from broker response")
	}
	if resp.StatusCode >= 400 {
		errResp := server_structs.SimpleApiResp{}
		log.Errorf("Failure (status code %d) when invoking the broker: %s", resp.StatusCode, string(responseBytes))
		if err = json.Unmarshal(responseBytes, &errResp); err != nil {
			err = errors.Errorf("Failure when invoking the broker (status code %d); unable to parse error message", resp.StatusCode)
		} else {
			err = errors.Errorf("Failure when invoking the broker (status code %d): %s", resp.StatusCode, errResp.Msg)
		}
		return
	}

	// Connection request sent; create a new host certificate in preparation for a response.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pelican"},
			CommonName:   originName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = []string{originName}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return
	}
	callbackResp := reversalCallbackResponse{
		Certificate: base64.StdEncoding.EncodeToString(derBytes),
	}
	callbackBytes, err := json.Marshal(&callbackResp)
	if err != nil {
		return
	}

	// Wait for the origin to callback to the cache's return endpoint; that HTTP handler
	// will write to the channel we originally posted.
	startTime := time.Now()
	timeoutCh := time.After(60 * time.Second)
	log.Debugf("Cache waiting for up to 60 seconds for the origin %s to callback", originName)
	select {
	case <-ctx.Done():
		log.Debug("Context has been cancelled while waiting for callback")
		err = ctx.Err()
		return
	case <-timeoutCh:
		elapsed := time.Since(startTime)
		fmt.Println("YOYOYOYO: timeout after : ", elapsed)
		log.Debug("Request has timed out when waiting for callback")
		err = errors.Errorf("YOYOYOYOYO Timeout when waiting for callback from origin - - -  %v", elapsed)
		return
	case writer := <-responseChannel:
		hj, ok := writer.(http.Hijacker)
		if !ok {
			log.Debug("Not able to hijack underlying TCP connection from server")
			resp := server_structs.SimpleApiResp{
				Msg:    "Unable to reverse TCP connection; HTTP/2 in use",
				Status: "error",
			}
			var respBytes []byte
			respBytes, err = json.Marshal(&resp)
			if err != nil {
				respBytes = []byte("")
				log.Error("Failed to serialize broker response:", err)
			} else {
				writer.Header().Set("Content-Type", "application/json")
			}
			writer.WriteHeader(http.StatusBadRequest)
			_, err = writer.Write(respBytes)
			if err != nil {
				log.Error("Failed to write response to client:", err)
			}
			return
		}

		// Write headers including explicit length, then flush out the body.
		// If we don't do both items, the response may still be buffered by time
		// we hijack the connection, leading to a client that indefinitely waits.
		writer.Header().Set("Content-Length", strconv.Itoa(len(callbackBytes)))
		writer.WriteHeader(http.StatusOK)
		if _, err = writer.Write(callbackBytes); err != nil {
			log.Error("Failed to write callback response to client:", err)
			return
		}
		flusher, ok := writer.(http.Flusher)
		if !ok {
			log.Error("Unable to flush data to client")
			return
		}
		flusher.Flush()

		conn, _, err = hj.Hijack()
		tlsConn, ok := conn.(*tls.Conn)
		if ok {
			// Once the cache receives the HTTP response, it'll close the TLS connection
			// That will cause a "close notify" to be sent back to the origin (this goroutine),
			// which indicates the last TLS record has been received.  That will cause an EOF
			// to be read from the TLS socket.
			for {
				ignoreBytes := make([]byte, 1024)
				_, err = tlsConn.Read(ignoreBytes)
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					log.Error("Failed to get close notification from cache")
					return
				}
			}
			conn = tlsConn.NetConn()
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				tlsConn.Close()
				log.Error("Remote connection is not over TCP")
				return
			}
			var fp *os.File
			fp, err = tcpConn.File()
			// Close the TCP connection out from underneath the TLS socket, preventing it
			// from sending spurious TLS records to the remote side and confusing it.
			tcpConn.Close()
			if err != nil {
				log.Error("Failed to duplicate TCP connection")
				return
			}
			defer fp.Close()
			conn, err = net.FileConn(fp)
			if err != nil {
				log.Error("Failed to convert file pointer to a TCP connection")
				return
			}
		}
	}
	return
}

// Callback to a given cache based on the request we got from a broker.
//
// The TCP socket used for the callback will be converted to a one-shot listener
// and reused with the origin as the "server".
func doCallback(ctx context.Context, brokerResp reversalRequest) (listener net.Listener, err error) {
	fmt.Println("YOYOYOYOY: Origin doing callback!!")
	log.Debugln("Origin starting callback to cache at", brokerResp.CallbackUrl)

	privateKey, err := privateKeyFromBytes(brokerResp.PrivateKey)
	if err != nil {
		return
	}
	originUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		return
	}
	serverNs := "/origins/" + originUrl.Host
	callbackReq := callbackRequest{RequestId: brokerResp.RequestId, OriginNs: serverNs}
	reqBytes, err := json.Marshal(&callbackReq)
	if err != nil {
		return
	}
	reqReader := bytes.NewReader(reqBytes)
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, brokerResp.CallbackUrl, reqReader)
	if err != nil {
		return
	}

	dur := time.Duration(5*time.Second - time.Duration(mrand.Intn(500))*time.Millisecond)
	req.Header.Set("X-Pelican-Timeout", dur.String())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-origin/"+config.GetVersion())

	cacheAud, err := url.Parse(brokerResp.CallbackUrl)
	if err != nil {
		return
	}
	cacheAud.Path = ""
	token, err := createToken(serverNs, param.Server_Hostname.GetString(), cacheAud.String(), token_scopes.Broker_Callback)
	if err != nil {
		err = errors.Wrap(err, "failure when constructing the cache callback token")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Create a copy of the default transport; instead of using the existing connection pool,
	// we will use a custom connection pool where we can hijack connections
	tr := config.GetTransport().Clone()
	hijackConnList := make([]*hijackConn, 0)
	hijackConnMutex := sync.Mutex{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return conn, err
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return conn, nil
		}
		// Take the connection and stash it onto our list.  After the client has shutdown, we will
		// steal the last TCP connection
		hj := &hijackConn{tcpConn, tcpConn}
		hijackConnMutex.Lock()
		hijackConnList = append(hijackConnList, hj)
		hijackConnMutex.Unlock()
		return hj, nil
	}

	// Cleanup any connections.  If we decide to steal one of them,
	// we will set hj.realConn to nil.
	defer func() {
		hijackConnMutex.Lock()
		defer hijackConnMutex.Unlock()
		for _, hj := range hijackConnList {
			if hj.realConn != nil {
				hj.realConn.Close()
			}
		}
	}()

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "Failure when calling back to cache %s for a reversal request", brokerResp.CallbackUrl)
		return
	}
	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrapf(err, "Failure when reading response from callback to cache %s", brokerResp.CallbackUrl)
		return
	}

	if resp.StatusCode >= 400 {
		errResp := server_structs.SimpleApiResp{}
		if err = json.Unmarshal(responseBytes, &errResp); err != nil {
			err = errors.Errorf("Failure when invoking cache %s callback (status code %d); unable to parse error message", brokerResp.CallbackUrl, resp.StatusCode)
		} else {
			err = errors.Errorf("Failure when invoking cache %s callback (status code %d): %s", brokerResp.CallbackUrl, resp.StatusCode, errResp.Msg)
		}
		log.Error("Callback failed:", err)
		return
	}

	log.Debugln("Origin finished callback to cache at", brokerResp.CallbackUrl)
	callbackResp := reversalCallbackResponse{}
	if err = json.Unmarshal(responseBytes, &callbackResp); err != nil {
		err = errors.Wrapf(err, "Failed to parse cache %s callback response", brokerResp.CallbackUrl)
		return
	}

	hostCertificate, err := base64.StdEncoding.DecodeString(callbackResp.Certificate)
	if err != nil {
		err = errors.Wrapf(err, "Failed to decode the cache %s certificate in response", brokerResp.CallbackUrl)
		return
	}

	// Send the "close notify" packet to the origin
	client.CloseIdleConnections()

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{hostCertificate},
			PrivateKey:  privateKey,
		}},
		NextProtos: []string{"http/1.1"},
	}

	var hj *hijackConn
	gotConn := false
	hijackConnMutex.Lock()
	if len(hijackConnList) > 0 {
		hj = hijackConnList[len(hijackConnList)-1]
		gotConn = true
	}
	hijackConnMutex.Unlock()
	if !gotConn {
		err = errors.New("Internal error: no new connection made to remote cache")
		return
	}

	// Create a new socket from the old socket; resets state in the
	// runtime to make it more like a "new" socket.
	fp, err := hj.realConn.File()
	if err != nil {
		err = errors.Wrap(err, "Failure when duplicating hijacked connection")
		return
	}
	hj.realConn.Close()
	newConn, err := net.FileConn(fp)
	if err != nil {
		err = errors.Wrap(err, "Failure when making socket from duplicated connection")
		return
	}
	fp.Close()
	revConn, ok := newConn.(*net.TCPConn)
	if !ok {
		err = errors.New("Failed to cast connection back to TCP socket")
		return
	}

	hj.realConn = nil
	listener = tls.NewListener(newOneShotListener(revConn), &tlsConfig)

	return
}

// Launch a goroutine that polls the broker endpoint for reversal requests
// The returned channel will produce listeners that are "one shot"; it's a
// TLS listener where you can invoke "Accept" once before it automatically
// closes itself.  It is the result of a successful connection reversal to
// a cache.
// func LaunchRequestMonitor(ctx context.Context, egrp *errgroup.Group, resultChan chan any) error {
// 	fedInfo, err := config.GetFederation(ctx)
// 	if err != nil {
// 		return err
// 	}

// 	brokerUrl := fedInfo.BrokerEndpoint
// 	if brokerUrl == "" {
// 		return errors.New("Broker service is not set or discovered; cannot enable broker functionality. Try setting Federation.BrokerUrl")
// 	}

// 	brokerEndpoint := brokerUrl + "/api/v1.0/broker/retrieve"
// 	originUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
// 	if err != nil {
// 		return err
// 	}
// 	serverNs := "/origins/" + originUrl.Host

// 	egrp.Go(func() error {
// 		sleepDuration := time.Second
// 		for {
// 			select {
// 			case <-ctx.Done():
// 				return ctx.Err()
// 			default:
// 				oReq := originRequest{
// 					Origin:   originUrl.Hostname(),
// 					Prefix:   param.Origin_FederationPrefix.GetString(),
// 					ServerNs: serverNs,
// 				}
// 				reqBytes, err := json.Marshal(&oReq)
// 				if err != nil {
// 					log.Errorln("JSON Marshal error:", err)
// 					return err
// 				}

// 				reqReader := bytes.NewReader(reqBytes)
// 				req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerEndpoint, reqReader)
// 				if err != nil {
// 					log.Errorln("Failed to create broker request:", err)
// 					return err
// 				}

// 				dur := param.Transport_ResponseHeaderTimeout.GetDuration() - time.Duration(mrand.Intn(500))*time.Millisecond
// 				req.Header.Set("X-Pelican-Timeout", dur.String())
// 				req.Header.Set("Content-Type", "application/json")
// 				req.Header.Set("User-Agent", "pelican-origin/"+config.GetVersion())

// 				brokerAud, err := url.Parse(fedInfo.BrokerEndpoint)
// 				if err != nil {
// 					log.Errorln("Failed to parse broker URL:", err)
// 					return err
// 				}
// 				brokerAud.Path = ""

// 				token, err := createToken(serverNs, param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Retrieve)
// 				if err != nil {
// 					log.Errorln("Failed to construct broker retrieve token:", err)
// 					return err
// 				}
// 				req.Header.Set("Authorization", "Bearer "+token)

// 				client := &http.Client{Transport: config.GetTransport()}
// 				resp, err := client.Do(req)
// 				if err != nil {
// 					log.Errorln("Broker request failed:", err)
// 					sleepDuration *= 2
// 					if sleepDuration > time.Minute {
// 						sleepDuration = time.Minute
// 					}
// 					time.Sleep(sleepDuration)
// 					continue
// 				}
// 				io.Copy(io.Discard, resp.Body) // Ensure full response read
// 				resp.Body.Close()

// 				if resp.StatusCode >= 400 {
// 					log.Errorf("Broker returned error (status: %d)", resp.StatusCode)
// 					return errors.New("broker request failed")
// 				}

// 				brokerResp := &brokerRetrievalResp{}
// 				err = json.Unmarshal(reqBytes, brokerResp)
// 				if err != nil {
// 					log.Errorln("Failed to unmarshal broker response:", err)
// 					return err
// 				}

// 				if brokerResp.Status == server_structs.RespOK {
// 					listener, err := doCallback(ctx, brokerResp.Request)
// 					if err != nil {
// 						log.Errorln("Callback error:", err)
// 						resultChan <- err
// 						return err
// 					}
// 					resultChan <- listener
// 				} else if brokerResp.Status == server_structs.RespFailed {
// 					log.Errorln("Broker error:", brokerResp.Msg)
// 				} else if brokerResp.Status != server_structs.RespPollTimeout {
// 					log.Errorf("Unexpected broker response: %s", brokerResp.Status)
// 				}

// 				sleepDuration = time.Second // Reset sleep duration
// 				time.Sleep(sleepDuration)
// 			}
// 		}
// 	})

// 	return nil
// }

func LaunchRequestMonitor(ctx context.Context, egrp *errgroup.Group, resultChan chan any) error {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return err
	}

	brokerUrl := fedInfo.BrokerEndpoint
	if brokerUrl == "" {
		return errors.New("Broker service is not set or discovered; cannot enable broker functionality. Try setting Federation.BrokerUrl")
	}

	brokerEndpoint := brokerUrl + "/api/v1.0/broker/retrieve"
	originUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		return err
	}
	serverNs := "/origins/" + originUrl.Host

	// Retrieve all exports
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return err
	}
	egrp.Go(func() error {
		sleepDuration := time.Second
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				allRequestsFailed := true // Track if every request in this iteration failed

				for _, export := range originExports {

					oReq := originRequest{
						Origin:   originUrl.Hostname(),
						Prefix:   export.FederationPrefix,
						ServerNs: serverNs,
					}

					reqBytes, err := json.Marshal(&oReq)
					if err != nil {
						log.Errorln("JSON Marshal error:", err)
						continue
					}

					reqReader := bytes.NewReader(reqBytes)
					req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerEndpoint, reqReader)
					if err != nil {
						log.Errorln("Failed to create broker request:", err)
						continue
					}

					dur := param.Transport_ResponseHeaderTimeout.GetDuration() - time.Duration(mrand.Intn(500))*time.Millisecond
					req.Header.Set("X-Pelican-Timeout", dur.String())
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("User-Agent", "pelican-origin/"+config.GetVersion())

					// ✅ Ensure the broker audience URL is correctly parsed
					brokerAud, err := url.Parse(fedInfo.BrokerEndpoint)
					if err != nil {
						log.Errorln("Failed to parse broker URL:", err)
						continue
					}
					brokerAud.Path = ""

					// ✅ Ensure a fresh token is created for every request
					token, err := createToken(serverNs, param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Retrieve)
					if err != nil {
						log.Errorln("Failed to construct broker retrieve token:", err)
						continue
					}

					req.Header.Set("Authorization", "Bearer "+token)

					client := &http.Client{Transport: config.GetTransport()}
					resp, err := client.Do(req)
					if err != nil {
						log.Errorln("Broker request failed:", err)
						continue
					}
					defer resp.Body.Close()

					responseBytes, err := io.ReadAll(resp.Body)
					if err != nil {
						log.Errorln("Failure when reading from broker response:", err)
						continue
					}

					if resp.StatusCode == 401 {
						log.Errorln("YOYOYOYOYO ERROR: Received 401 Unauthorized. Token might be invalid or expired.")
						continue
					}

					if resp.StatusCode >= 400 {
						log.Errorf("Broker returned error (status: %d)", resp.StatusCode)
						continue
					}

					brokerResp := &brokerRetrievalResp{}
					err = json.Unmarshal(responseBytes, brokerResp)
					if err != nil {
						log.Errorf("Failed to unmarshal response: %v. Response body: %s", err, string(responseBytes))
						continue
					}

					if brokerResp.Status == server_structs.RespOK {
						listener, err := doCallback(ctx, brokerResp.Request)
						if err != nil {
							log.Errorln("Failed to callback to the cache:", err)
							resultChan <- err
							continue
						}
						resultChan <- listener
					} else if brokerResp.Status == server_structs.RespFailed {
						log.Errorln("Broker error:", brokerResp.Msg)
					} else if brokerResp.Status != server_structs.RespPollTimeout {
						log.Errorf("Unexpected broker response: %s", brokerResp.Status)
					}
					allRequestsFailed = false
				}

				// ✅ Increase sleep time only if all requests failed
				if allRequestsFailed {
					sleepDuration *= 2
					if sleepDuration > time.Minute {
						sleepDuration = time.Minute
					}
					log.Warnf("All requests failed, increasing sleep time to %s", sleepDuration)
				} else {
					sleepDuration = time.Second // ✅ Reset sleep duration on success
				}

				time.Sleep(sleepDuration)
			}
		}
	})

	return nil
}
