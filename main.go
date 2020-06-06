package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/hashicorp/vault/api"
	"github.com/minio/minio-go"
)

/* Config (from environment for now) */
var esHost = os.Getenv("ELASTICSEARCH_URL") // TODO: handle multiple
var esUsername = os.Getenv("ELASTICSEARCH_USERNAME")
var esPassword = os.Getenv("ELASTICSEARCH_PASSWORD")
var backupId = os.Getenv("BACKUP_ID")
var vaultAddr = os.Getenv("VAULT_ADDR")
var vaultToken = os.Getenv("VAULT_TOKEN")
var passphraseSecretPath = os.Getenv("PASSPHRASE_SECRET_PATH")
var passphraseSecretKey = os.Getenv("PASSPHRASE_SECRET_KEY")
var storageURL = os.Getenv("STORAGE_URL")
var storageAccessKey = os.Getenv("STORAGE_ACCESS_KEY")
var storageSecretKey = os.Getenv("STORAGE_SECRET_KEY")

func _latest_snapshot() (string, error) {
	cfg := elasticsearch.Config{
		Addresses: []string{
			esHost,
		},
		Username: esUsername,
		Password: esPassword,
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   10,
			ResponseHeaderTimeout: time.Second,
			DialContext:           (&net.Dialer{Timeout: time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS11,
				InsecureSkipVerify: true,
			},
		},
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"source.id.keyword": backupId,
			},
		},
	}
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		log.Fatalf("Error encoding query: %s", err)
	}

	res, err := es.Search(
		es.Search.WithIndex("backups-*"),
		es.Search.WithBody(&buf),
		es.Search.WithSize(1),
		es.Search.WithSort("@timestamp:desc"),
	)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var mapResp map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&mapResp)
	if err != nil {
		return "", err
	}
	if mapResp["error"] != nil {
		error := mapResp["error"].(map[string]interface{})
		reason := error["reason"].(string)
		return "", fmt.Errorf(reason)
	}

	// Iterate the document "hits" returned by API call
	hit := mapResp["hits"].(map[string]interface{})["hits"].([]interface{})[0]
	doc := hit.(map[string]interface{})
	source := doc["_source"]
	stats := source.(map[string]interface{})["stats"]
	dumpedfiles := stats.(map[string]interface{})["dumpedfiles"]
	file := dumpedfiles.([]interface{})[0]

	return file.(string), nil
}

func _fetch_passphrase() (*string, error) {
	config := &api.Config{Address: vaultAddr}
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Connecting to Vault: %w", err)
	}
	client.SetToken(vaultToken)
	secret, err := client.Logical().Read(passphraseSecretPath)
	if err != nil {
		return nil, fmt.Errorf("Reading passphrase key: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("No secret found at specified path: %s", passphraseSecretPath)
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("No 'data' found at specified path (%s).", passphraseSecretPath)
	}
	passphrase, ok := data[passphraseSecretKey].(string)
	if !ok {
		return nil, fmt.Errorf("No '%s' key found at specified path (%s).", passphraseSecretKey, passphraseSecretPath)
	}
	return &passphrase, nil
}

func readerFile(r io.Reader) (*os.File, error) {
	reader, writer, err := os.Pipe()

	if err != nil {
		return nil, err
	}

	go func() {
		io.Copy(writer, r)
		writer.Close()
	}()

	return reader, nil
}

func handleError(w http.ResponseWriter, err string) {
	http.Error(w, err, http.StatusInternalServerError)
	fmt.Fprintf(os.Stderr, "ERROR: "+err+"\n")
}

func download(w http.ResponseWriter, req *http.Request) {
	// Obtain Vault key for backup passphrase. We can't do much without that.
	passphrase, err := _fetch_passphrase()
	if err != nil {
		handleError(w, "Fetching passphrase from Vault: "+err.Error())
		return
	}
	if passphrase == nil {
		handleError(w, "Empty passphrase returned from Vault")
		return
	}

	// Perform a query to obtain the latest snapshot URL to prepare to download.
	snapshot_id, err := _latest_snapshot()
	if err != nil {
		handleError(w, "Fetching latest snapshot id from backups index: "+err.Error())
		return
	}

	// Parse the snapshot ID to obtain the path information
	u, err := url.Parse(snapshot_id)
	if err != nil {
		handleError(w, "Unable to parse url ("+snapshot_id+") for latest snapshot id from backups index: "+err.Error())
		return
	}

	// Obtain an input stream reading the snapshot object from it's bucket
	minioClient, err := minio.New(storageURL, storageAccessKey, storageSecretKey, true)
	if err != nil {
		handleError(w, "Unable to obtain handle on object storage: "+err.Error())
		return
	}
	object, err := minioClient.GetObject(u.Host, strings.TrimPrefix(u.Path, "/"), minio.GetObjectOptions{})
	if err != nil {
		handleError(w, "Error with GetObject: "+err.Error())
		return
	}

	// Start up a GnuPG decrypt process
	cmd := exec.Command("gpg", "--batch", "--passphrase-fd", "3")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		handleError(w, "GnuPG stdin: "+err.Error())
		return
	}

	// Feed passphrase in on an extra file descriptor
	phrasefd, err := readerFile(strings.NewReader(*passphrase))
	if err != nil {
		handleError(w, "Unable to initialise GnuPG passphrase reader: "+err.Error())
		return
	}
	defer phrasefd.Close()

	// Grab descriptor for decrypted output from GnuPG
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		handleError(w, "GnuPG stdout: "+err.Error())
		return
	}

	// Loop reading from object and writing to GnuPG
	go func() {
		//fmt.Println("Entering input loop (object to GnuPG)")
		for {
			bytecount, err := io.CopyN(stdin, object, 1000000)
			if err != nil {
				handleError(w, "Transferring object from storage: "+err.Error())
				cmd.Process.Kill()
				return
			}
			//fmt.Printf("Read %d\n", bytecount)
			if bytecount <= 0 {
				break
			}
		}
		//fmt.Println("Exiting input loop")
	}()

	// Loop reading from GnuPG and writing to response
	go func() {
		//fmt.Println("Entering output loop (GnuPG to response)")
		for {
			bytecount, err := io.CopyN(w, stdout, 1000000)
			if err != nil {
				handleError(w, "Transferring decrypted file to response: "+err.Error())
				cmd.Process.Kill()
				return
			}
			//fmt.Printf("Wrote %d\n", bytecount)
			if bytecount <= 0 {
				break
			}
		}
		//fmt.Println("Exiting output loop")
	}()

	// Run the process and wait for it to complete
	cmd.ExtraFiles = []*os.File{phrasefd}
	err = cmd.Run()
	if err != nil {
		handleError(w, "Error running GnuPG process: "+err.Error())
		return
	}

	// TODO: Log some kind of auditing/metrics data with auth info, IP addresses, timings
}

func main() {
	http.HandleFunc("/download", download)
	http.ListenAndServe(":8000", nil)
}
