package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// CredentialEntry holds a stored login token for a cluster endpoint.
type CredentialEntry struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// credentialsFile holds all stored credentials keyed by host identifier.
type credentialsFile struct {
	Clusters map[string]CredentialEntry `json:"clusters"`
}

func credentialsPath() string {
	return filepath.Join(ConfigDir(), "credentials.json")
}

func loadCredentials() (*credentialsFile, error) {
	data, err := os.ReadFile(credentialsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &credentialsFile{Clusters: map[string]CredentialEntry{}}, nil
		}
		return nil, err
	}
	var cf credentialsFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return &credentialsFile{Clusters: map[string]CredentialEntry{}}, nil
	}
	if cf.Clusters == nil {
		cf.Clusters = map[string]CredentialEntry{}
	}
	return &cf, nil
}

func saveCredentials(cf *credentialsFile) error {
	dir := filepath.Dir(credentialsPath())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credentialsPath(), data, 0600)
}

// clusterKey returns a unique key for the current cluster connection.
// Uses LV_HOST env var for remote mode, or "local" for local daemon mode.
func clusterKey() string {
	if host := os.Getenv("LV_HOST"); host != "" {
		return host
	}
	return "local"
}

// SaveCredential stores a login token for the current cluster.
func SaveCredential(entry CredentialEntry) error {
	cf, err := loadCredentials()
	if err != nil {
		return err
	}
	cf.Clusters[clusterKey()] = entry
	return saveCredentials(cf)
}

// LoadCredential returns the stored credential for the current cluster, if any.
func LoadCredential() (*CredentialEntry, error) {
	cf, err := loadCredentials()
	if err != nil {
		return nil, err
	}
	entry, ok := cf.Clusters[clusterKey()]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}

// DeleteCredential removes the stored credential for the current cluster.
func DeleteCredential() error {
	cf, err := loadCredentials()
	if err != nil {
		return err
	}
	delete(cf.Clusters, clusterKey())
	return saveCredentials(cf)
}
