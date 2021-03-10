/*
Copyright 2016 Gravitational, Inc.

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

package client

import (
	"bufio"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/sirupsen/logrus"

	"github.com/gravitational/trace"
)

const (
	defaultKeyDir      = ProfileDir
	fileExtPub         = ".pub"
	fileExtSSHCert     = "-cert.pub"
	fileExtTLSCert     = "-x509.pem"
	sessionKeyDir      = "keys"
	fileNameKnownHosts = "known_hosts"
	fileNameTLSCerts   = "certs.pem"
	sshDirSuffix       = "-ssh"
	kubeDirSuffix      = "-kube"
	dbDirSuffix        = "-db"

	// profileDirPerms is the default permissions applied to the profile
	// directory (usually ~/.tsh)
	profileDirPerms os.FileMode = 0700

	// keyFilePerms is the default permissions applied to key files (.cert, .key, pub)
	// under ~/.tsh
	keyFilePerms os.FileMode = 0600
)

// LocalKeyStore interface allows for different storage backends for tsh to
// load/save its keys.
//
// The _only_ filesystem-based implementation of LocalKeyStore is declared
// below (FSLocalKeyStore)
type LocalKeyStore interface {
	// AddKey adds the given session key for the proxy and username to the
	// storage backend.
	AddKey(proxy string, username string, key *Key) error

	// GetKey returns the user's key including the specified certs.
	GetKey(proxy, username, clusterName string, opts ...CertOption) (*Key, error)

	// DeleteKey deletes the user's key with all its certs.
	DeleteKey(proxyHost, username string) error

	// DeleteCerts deletes only the specified certs of the user's key,
	// keeping the private key intact.
	DeleteCerts(proxyHost, username string, opts ...CertOption) error

	// DeleteKeys removes all session keys from disk.
	DeleteKeys() error

	// AddKnownHostKeys adds the public key to the list of known hosts for
	// a hostname.
	AddKnownHostKeys(hostname string, keys []ssh.PublicKey) error

	// GetKnownHostKeys returns all public keys for a hostname.
	GetKnownHostKeys(hostname string) ([]ssh.PublicKey, error)

	// SaveCerts saves trusted TLS certificates of certificate authorities.
	SaveCerts(proxy string, cas []auth.TrustedCerts) error

	// GetCertsPEM gets trusted TLS certificates of certificate authorities.
	// Each returned byte slice contains an individual PEM block.
	GetCertsPEM(proxy string) ([][]byte, error)
}

// FSLocalKeyStore implements LocalKeyStore interface using the filesystem.
// Here's the file layout for the FS store:
//
// ~/.tsh/
// ├── known_hosts                   --> trusted certificate authorities (their keys) in a format similar to known_hosts
// └── keys
//    ├── one.example.com            --> Proxy hostname
//    │   ├── certs.pem              --> TLS CA certs for the Teleport CA
//    │   ├── foo                    --> RSA Private Key for user "foo"
//    │   ├── foo.pub                --> Public Key
//    │   ├── foo-x509.pem           --> TLS client certificate for Auth Server
//    │   ├── foo-ssh                --> SSH certs for user "foo"
//    │   │   ├── root-cert.pub      --> SSH cert for Teleport cluster "root"
//    │   │   └── leaf-cert.pub      --> SSH cert for Teleport cluster "leaf"
//    │   ├── foo-kube               --> Kubernetes certs for user "foo"
//    │   │   ├── root               --> Kubernetes certs for Teleport cluster "root"
//    │   │   │   ├── kubeA-x509.pem --> TLS cert for Kubernetes cluster "kubeA"
//    │   │   │   └── kubeB-x509.pem --> TLS cert for Kubernetes cluster "kubeB"
//    │   │   └── leaf               --> Kubernetes certs for Teleport cluster "leaf"
//    │   │       └── kubeC-x509.pem --> TLS cert for Kubernetes cluster "kubeC"
//    │   └── foo-db                 --> Database access certs for user "foo"
//    │       ├── root               --> Database access certs for cluster "root"
//    │       │   ├── dbA-x509.pem   --> TLS cert for database service "dbA"
//    │       │   └── dbB-x509.pem   --> TLS cert for database service "dbB"
//    │       └── leaf               --> Database access certs for cluster "leaf"
//    │           └── dbC-x509.pem   --> TLS cert for database service "dbC"
//    └── two.example.com
//        ├── certs.pem
//        ├── bar
//        ├── bar.pub
//        ├── bar-x509.pem
//        └── bar-ssh
//            └── clusterA-cert.pub
type FSLocalKeyStore struct {
	// log holds the structured logger.
	log *logrus.Entry

	// KeyDir is the directory where all keys are stored.
	KeyDir string
}

// NewFSLocalKeyStore creates a new filesystem-based local keystore object
// and initializes it.
//
// If dirPath is empty, sets it to ~/.tsh.
func NewFSLocalKeyStore(dirPath string) (s *FSLocalKeyStore, err error) {
	dirPath, err = initKeysDir(dirPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &FSLocalKeyStore{
		log: logrus.WithFields(logrus.Fields{
			trace.Component: teleport.ComponentKeyStore,
		}),
		KeyDir: dirPath,
	}, nil
}

// AddKey adds a new key to the session store. If a key for the host is already
// stored, overwrites it.
func (fs *FSLocalKeyStore) AddKey(host, username string, key *Key) error {
	if key.ClusterName == "" {
		return trace.BadParameter("key must have ClusterName set to be added to the store")
	}
	dirPath, err := fs.dirFor(host, true)
	if err != nil {
		return trace.Wrap(err)
	}

	writeBytes := func(fname string, data []byte) error {
		fp := filepath.Join(dirPath, fname)
		if err := os.MkdirAll(filepath.Dir(fp), os.ModeDir|profileDirPerms); err != nil {
			return trace.Wrap(err)
		}
		err := ioutil.WriteFile(fp, data, keyFilePerms)
		if err != nil {
			fs.log.Error(err)
		}
		return err
	}

	if err = writeBytes(username, key.Priv); err != nil {
		return trace.Wrap(err)
	}
	if err = writeBytes(username+fileExtPub, key.Pub); err != nil {
		return trace.Wrap(err)
	}
	if err = writeBytes(username+fileExtTLSCert, key.TLSCert); err != nil {
		return trace.Wrap(err)
	}

	if err = writeBytes(filepath.Join(username+sshDirSuffix, key.ClusterName+fileExtSSHCert), key.Cert); err != nil {
		return trace.Wrap(err)
	}
	// TODO(awly): unit test this.
	for kubeCluster, cert := range key.KubeTLSCerts {
		// Prevent directory traversal via a crafted kubernetes cluster name.
		//
		// This will confuse cluster cert loading (GetKey will return
		// kubernetes cluster names different from the ones stored here), but I
		// don't expect any well-meaning user to create bad names.
		kubeCluster = filepath.Clean(kubeCluster)

		fname := filepath.Join(username+kubeDirSuffix, key.ClusterName, kubeCluster+fileExtTLSCert)
		if err := writeBytes(fname, cert); err != nil {
			return trace.Wrap(err)
		}
	}
	for db, cert := range key.DBTLSCerts {
		fname := filepath.Join(username+dbDirSuffix, key.ClusterName, filepath.Clean(db)+fileExtTLSCert)
		if err := writeBytes(fname, cert); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// DeleteKey deletes the user's key with all its certs.
func (fs *FSLocalKeyStore) DeleteKey(host, username string) error {
	dirPath, err := fs.dirFor(host, false)
	if err != nil {
		return trace.Wrap(err)
	}
	files := []string{
		filepath.Join(dirPath, username),
		filepath.Join(dirPath, username+fileExtPub),
		filepath.Join(dirPath, username+fileExtTLSCert),
	}
	for _, fn := range files {
		if err = os.Remove(fn); err != nil {
			return trace.Wrap(err)
		}
	}

	return fs.DeleteCerts(host, username, WithAllCerts()...)
}

// DeleteCerts deletes only the specified certs of the user's key,
// keeping the private key intact.
//
// Useful when needing to log out of a specific service, like a particular
// database proxy.
func (fs *FSLocalKeyStore) DeleteCerts(host, username string, opts ...CertOption) error {
	dirPath, err := fs.dirFor(host, false)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, o := range opts {
		if err := o.deleteFromKey(dirPath, username); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// DeleteKeys removes all session keys from disk.
func (fs *FSLocalKeyStore) DeleteKeys() error {
	dirPath := filepath.Join(fs.KeyDir, sessionKeyDir)

	err := os.RemoveAll(dirPath)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// GetKey returns the user's key including the specified certs.
// clusterName can be left empty if there are no cluster-dependent CertOptions.
// If the key is not found, returns trace.NotFound error.
func (fs *FSLocalKeyStore) GetKey(proxyHost, username, clusterName string, opts ...CertOption) (*Key, error) {
	dirPath, err := fs.dirFor(proxyHost, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	_, err = ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, trace.NotFound("no session keys for %v in %v", username, proxyHost)
	}

	pub, err := ioutil.ReadFile(filepath.Join(dirPath, username+fileExtPub))
	if err != nil {
		fs.log.Error(err)
		return nil, trace.Wrap(err)
	}
	priv, err := ioutil.ReadFile(filepath.Join(dirPath, username))
	if err != nil {
		fs.log.Error(err)
		return nil, trace.Wrap(err)
	}
	tlsCertFile := filepath.Join(dirPath, username+fileExtTLSCert)
	tlsCert, err := ioutil.ReadFile(tlsCertFile)
	if err != nil {
		fs.log.Error(err)
		return nil, trace.Wrap(err)
	}
	tlsCA, err := fs.GetCertsPEM(proxyHost)
	if err != nil {
		fs.log.Error(err)
		return nil, trace.Wrap(err)
	}

	key := &Key{
		Pub:       pub,
		Priv:      priv,
		TLSCert:   tlsCert,
		ProxyHost: proxyHost,
		TrustedCA: []auth.TrustedCerts{{
			TLSCertificates: tlsCA,
		}},
		ClusterName: clusterName,
	}

	for _, o := range opts {
		if err := o.addToKey(key, dirPath, username, fs.log); err != nil {
			fs.log.Error(err)
			return nil, trace.Wrap(err)
		}
	}

	tlsCertExpiration, err := key.TeleportTLSCertValidBefore()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fs.log.Debugf("Returning Teleport TLS certificate %q valid until %q.",
		tlsCertFile, tlsCertExpiration)

	// Note, we may be returning expired certificates here, that is okay. If a
	// certificate is expired, it's the responsibility of the TeleportClient to
	// perform cleanup of the certificates and the profile.

	return key, nil
}

// CertOption is an additional step to run when loading (LocalKeyStore.GetKey)
// or deleting (LocalKeyStore.DeleteKey) keys. These are the steps skipped by
// default to reduce the amount of work that Get/DeleteKey performs by default.
type CertOption interface {
	addToKey(key *Key, dirPath, username string, log logrus.FieldLogger) error
	deleteFromKey(dirPath, username string) error
}

// WithAllCerts lists all known CertOptions.
func WithAllCerts() []CertOption {
	return []CertOption{WithSSHCerts{}, WithKubeCerts{}, WithDBCerts{}}
}

// WithSSHCerts is a CertOption for handling SSH certificates.
type WithSSHCerts struct{}

func (o WithSSHCerts) addToKey(key *Key, dirPath, username string, log logrus.FieldLogger) error {
	certFile := filepath.Join(dirPath, username+sshDirSuffix, key.ClusterName+fileExtSSHCert)
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	key.Cert = data

	// Validate the key loaded from disk.
	if err = key.CheckCert(); err != nil {
		// KeyStore should return expired certificates.
		if !utils.IsCertExpiredError(err) {
			return trace.Wrap(err)
		}
	}

	// Report expiration date.
	certExpiration, err := key.CertValidBefore()
	if err != nil {
		return trace.Wrap(err)
	}
	log.Debugf("Returning SSH certificate %q valid until %q.", certFile, certExpiration)
	return nil
}

func (o WithSSHCerts) deleteFromKey(dirPath, username string) error {
	certsDir := filepath.Join(dirPath, username+sshDirSuffix)
	return trace.ConvertSystemError(os.RemoveAll(certsDir))
}

// WithKubeCerts is a CertOption for handling kubernetes certificates.
type WithKubeCerts struct{}

// TODO(awly): unit test this.
func (o WithKubeCerts) addToKey(key *Key, dirPath, username string, log logrus.FieldLogger) error {
	kubeDir := filepath.Join(dirPath, username+kubeDirSuffix, key.ClusterName)
	kubeFiles, err := ioutil.ReadDir(kubeDir)
	if err != nil && !os.IsNotExist(err) {
		return trace.ConvertSystemError(err)
	}
	if key.KubeTLSCerts == nil {
		key.KubeTLSCerts = make(map[string][]byte)
	}
	for _, fi := range kubeFiles {
		data, err := ioutil.ReadFile(filepath.Join(kubeDir, fi.Name()))
		if err != nil {
			return trace.ConvertSystemError(err)
		}
		kubeCluster := strings.TrimSuffix(filepath.Base(fi.Name()), fileExtTLSCert)
		key.KubeTLSCerts[kubeCluster] = data
	}
	return nil
}

func (o WithKubeCerts) deleteFromKey(dirPath, username string) error {
	kubeCertsDir := filepath.Join(dirPath, username+kubeDirSuffix)
	return trace.ConvertSystemError(os.RemoveAll(kubeCertsDir))
}

// WithDBCerts is a CertOption for handling database access certificates.
type WithDBCerts struct {
	teleportClusterName, dbName string
}

func (o WithDBCerts) addToKey(key *Key, dirPath, username string, log logrus.FieldLogger) error {
	dbDir := filepath.Join(dirPath, username+dbDirSuffix, key.ClusterName)
	dbFiles, err := ioutil.ReadDir(dbDir)
	if err != nil && !os.IsNotExist(err) {
		return trace.Wrap(err)
	}
	if key.DBTLSCerts == nil {
		key.DBTLSCerts = make(map[string][]byte)
	}
	for _, fi := range dbFiles {
		data, err := ioutil.ReadFile(filepath.Join(dbDir, fi.Name()))
		if err != nil {
			return trace.Wrap(err)
		}
		dbName := strings.TrimSuffix(filepath.Base(fi.Name()), fileExtTLSCert)
		key.DBTLSCerts[dbName] = data
	}
	return nil
}

func (o WithDBCerts) deleteFromKey(dirPath, username string) error {
	// If database name is specified, remove only that cert.
	// If only Teleport cluster is specified, remove all DB certs within that cluster.
	// Otherwise remove certs for all databases the user is logged into.
	dbPath := filepath.Join(dirPath, username+dbDirSuffix)
	if o.teleportClusterName != "" {
		dbPath = filepath.Join(dbPath, o.teleportClusterName)
		if o.dbName != "" {
			err := os.Remove(filepath.Join(dbPath, o.dbName+fileExtTLSCert))
			return trace.ConvertSystemError(err)
		}
	}
	return trace.ConvertSystemError(os.RemoveAll(dbPath))
}

// SaveCerts saves trusted TLS certificates of certificate authorities
func (fs *FSLocalKeyStore) SaveCerts(proxy string, cas []auth.TrustedCerts) (retErr error) {
	dir, err := fs.dirFor(proxy, true)
	if err != nil {
		return trace.Wrap(err)
	}
	fp, err := os.OpenFile(filepath.Join(dir, fileNameTLSCerts), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0640)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	defer utils.StoreErrorOf(fp.Close, &retErr)
	for _, ca := range cas {
		for _, cert := range ca.TLSCertificates {
			if _, err := fp.Write(cert); err != nil {
				return trace.ConvertSystemError(err)
			}
			if _, err := fmt.Fprintln(fp); err != nil {
				return trace.ConvertSystemError(err)
			}
		}
	}
	return fp.Sync()
}

// GetCertsPEM returns trusted TLS certificates of certificate authorities PEM
// blocks.
func (fs *FSLocalKeyStore) GetCertsPEM(proxy string) ([][]byte, error) {
	dir, err := fs.dirFor(proxy, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	data, err := ioutil.ReadFile(filepath.Join(dir, fileNameTLSCerts))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var blocks [][]byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			fs.log.Debugf("Skipping PEM block type=%v headers=%v.", block.Type, block.Headers)
			continue
		}
		// rest contains the remainder of data after reading a block.
		// Therefore, the block length is len(data) - len(rest).
		// Use that length to slice the block from the start of data.
		blocks = append(blocks, data[:len(data)-len(rest)])
		data = rest
	}
	return blocks, nil
}

// AddKnownHostKeys adds a new entry to 'known_hosts' file
func (fs *FSLocalKeyStore) AddKnownHostKeys(hostname string, hostKeys []ssh.PublicKey) (retErr error) {
	fp, err := os.OpenFile(filepath.Join(fs.KeyDir, fileNameKnownHosts), os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	defer utils.StoreErrorOf(fp.Close, &retErr)
	// read all existing entries into a map (this removes any pre-existing dupes)
	entries := make(map[string]int)
	output := make([]string, 0)
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		line := scanner.Text()
		if _, exists := entries[line]; !exists {
			output = append(output, line)
			entries[line] = 1
		}
	}
	// add every host key to the list of entries
	for i := range hostKeys {
		fs.log.Debugf("Adding known host %s with key: %v", hostname, sshutils.Fingerprint(hostKeys[i]))
		bytes := ssh.MarshalAuthorizedKey(hostKeys[i])
		line := strings.TrimSpace(fmt.Sprintf("%s %s", hostname, bytes))
		if _, exists := entries[line]; !exists {
			output = append(output, line)
		}
	}
	// re-create the file:
	_, err = fp.Seek(0, 0)
	if err != nil {
		return trace.Wrap(err)
	}
	if err = fp.Truncate(0); err != nil {
		return trace.Wrap(err)
	}
	for _, line := range output {
		fmt.Fprintf(fp, "%s\n", line)
	}
	return fp.Sync()
}

// GetKnownHostKeys returns all known public keys from 'known_hosts'
func (fs *FSLocalKeyStore) GetKnownHostKeys(hostname string) ([]ssh.PublicKey, error) {
	bytes, err := ioutil.ReadFile(filepath.Join(fs.KeyDir, fileNameKnownHosts))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trace.Wrap(err)
	}
	var (
		pubKey    ssh.PublicKey
		retval    []ssh.PublicKey = make([]ssh.PublicKey, 0)
		hosts     []string
		hostMatch bool
	)
	for err == nil {
		_, hosts, pubKey, _, bytes, err = ssh.ParseKnownHosts(bytes)
		if err == nil {
			hostMatch = (hostname == "")
			if !hostMatch {
				for i := range hosts {
					if hosts[i] == hostname {
						hostMatch = true
						break
					}
				}
			}
			if hostMatch {
				retval = append(retval, pubKey)
			}
		}
	}
	if err != io.EOF {
		return nil, trace.Wrap(err)
	}
	return retval, nil
}

// dirFor returns the path to the session keys for a given host. The value
// for fs.KeyDir is typically "~/.tsh", sessionKeyDir is typically "keys",
// and proxyHost typically has values like "proxy.example.com".
//
// If the create flag is true, the directory will be created if it does
// not exist.
func (fs *FSLocalKeyStore) dirFor(proxyHost string, create bool) (string, error) {
	dirPath := filepath.Join(fs.KeyDir, sessionKeyDir, proxyHost)

	if create {
		if err := os.MkdirAll(dirPath, profileDirPerms); err != nil {
			fs.log.Error(err)
			return "", trace.ConvertSystemError(err)
		}
	}

	return dirPath, nil
}

// initKeysDir initializes the keystore root directory. Usually it is ~/.tsh
func initKeysDir(dirPath string) (string, error) {
	var err error
	// not specified? use `~/.tsh`
	if dirPath == "" {
		u, err := user.Current()
		if err != nil {
			dirPath = os.TempDir()
		} else {
			dirPath = u.HomeDir
		}
		dirPath = filepath.Join(dirPath, defaultKeyDir)
	}
	// create if doesn't exist:
	_, err = os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(dirPath, os.ModeDir|profileDirPerms)
			if err != nil {
				return "", trace.ConvertSystemError(err)
			}
		} else {
			return "", trace.Wrap(err)
		}
	}

	return dirPath, nil
}

// noLocalKeyStore is a LocalKeyStore representing the absence of a keystore.
// All methods return errors. This exists to avoid nil checking everywhere in
// LocalKeyAgent and prevent nil pointer panics.
type noLocalKeyStore struct{}

var errNoLocalKeyStore = trace.NotFound("there is no local keystore")

func (noLocalKeyStore) AddKey(proxy string, username string, key *Key) error {
	return errNoLocalKeyStore
}
func (noLocalKeyStore) GetKey(proxy, username, clusterName string, opts ...CertOption) (*Key, error) {
	return nil, errNoLocalKeyStore
}
func (noLocalKeyStore) DeleteKey(proxyHost, username string) error {
	return errNoLocalKeyStore
}
func (noLocalKeyStore) DeleteCerts(proxyHost, username string, opts ...CertOption) error {
	return errNoLocalKeyStore
}
func (noLocalKeyStore) DeleteKeys() error { return errNoLocalKeyStore }
func (noLocalKeyStore) AddKnownHostKeys(hostname string, keys []ssh.PublicKey) error {
	return errNoLocalKeyStore
}
func (noLocalKeyStore) GetKnownHostKeys(hostname string) ([]ssh.PublicKey, error) {
	return nil, errNoLocalKeyStore
}
func (noLocalKeyStore) SaveCerts(proxy string, cas []auth.TrustedCerts) error {
	return errNoLocalKeyStore
}
func (noLocalKeyStore) GetCertsPEM(proxy string) ([][]byte, error) { return nil, errNoLocalKeyStore }
