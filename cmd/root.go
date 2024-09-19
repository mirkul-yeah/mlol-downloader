package cmd

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
)

var passphrases []string

type LCPL struct {
	ID         *string `json:"id"`
	Encryption struct {
		Profile    string `json:"profile"`
		ContentKey struct {
			Algorithm      string `json:"algorithm"`
			EncryptedValue string `json:"encrypted_value"`
		} `json:"content_key"`
		UserKey struct {
			Algorithm string `json:"algorithm"`
			KeyCheck  string `json:"key_check"`
		} `json:"user_key"`
	} `json:"encryption"`
	Links []struct {
		Rel  string `json:"rel"`
		HRef string `json:"href"`
		Type string `json:"type"`
	} `json:"links"`
}

type XMLEncryption struct {
	EncryptedData []struct {
		EncryptionMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"EncryptionMethod"`
		CipherData struct {
			CipherReference struct {
				URI string `xml:"URI,attr"`
			} `xml:"CipherReference"`
		} `xml:"CipherData"`
	} `xml:"EncryptedData"`
}

type EpubContainer struct {
	Rootfiles struct {
		Rootfile struct {
			FullPath string `xml:"full-path,attr"`
		} `xml:"rootfile"`
	} `xml:"rootfiles"`
}

type EpubPackage struct {
	Metadata struct {
		Title   string `xml:"title"`
		Creator struct {
			Text string `xml:",chardata"`
		} `xml:"creator"`
	} `xml:"metadata"`
}

var masterkey = [64]byte{
	179, 160, 124, 77, 66, 136, 14, 105, 57, 142, 5, 57, 36, 5, 5, 14, 254, 234, 6, 100, 192,
	182, 56, 183, 201, 134, 85, 111, 169, 181, 141, 119, 179, 26, 64, 235, 106, 79, 219, 161,
	228, 83, 114, 41, 217, 247, 121, 218, 173, 28, 196, 30, 233, 104, 21, 60, 183, 31, 39, 220,
	150, 150, 212, 15,
}

// Core encryption in Readium LCP Profile 1.0
//
// Encrypt a key to an array of byte
func transformProfile10(input_hash []byte) []byte {

	currentHash := []byte(input_hash)
	for _, bvalue := range masterkey {
		currentHash = append(currentHash, bvalue)
		h := sha256.New()
		h.Write(currentHash)
		currentHash = h.Sum(nil)
	}
	return currentHash
}

// Decrypt a byte data with a key, using Readium LCP Profile 1.0
func dataDecryptLCP(data []byte, hexKey []byte) ([]byte, error) {
	iv := data[:16]
	cipherText := data[16:]

	block, err := aes.NewCipher(hexKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	padding := decrypted[len(decrypted)-1]
	if int(padding) > len(decrypted) {
		return nil, errors.New("padding error")
	}
	unpadded := decrypted[:len(decrypted)-int(padding)]

	return unpadded, nil
}

func MainMlol(cmd *cobra.Command, args []string) {
	// Open our jsonFile
	jsonFile, err := os.Open(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var lcpl LCPL
	json.Unmarshal(byteValue, &lcpl)

	// Check Json fields
	if lcpl.ID == nil {
		fmt.Println("File di Licenza non valido")
		return
	}
	// Check encryption parameters
	if (lcpl.Encryption.Profile != "http://readium.org/lcp/profile-1.0") ||
		(lcpl.Encryption.ContentKey.Algorithm != "http://www.w3.org/2001/04/xmlenc#aes256-cbc") ||
		(lcpl.Encryption.UserKey.Algorithm != "http://www.w3.org/2001/04/xmlenc#sha256") {
		fmt.Println("Parametro di crittazione non gestito")
		return
	}
	decryptedContentKey := findPassphrase(lcpl)
	if decryptedContentKey == nil {
		fmt.Println("Nessuna passphrase valida")
		return
	}
	encryptedFile := getPubblication(lcpl)
	if encryptedFile == nil {
		return
	}
	encr_files, err := findEncryptedEbookFilenames(*encryptedFile)
	if err == nil {
		// eBook!

		// open source zip file
		zipReader, err := zip.OpenReader(*encryptedFile)
		if err != nil {
			fmt.Printf("Errore durante la lettura del file %s\n", *encryptedFile)
			return
		}
		defer zipReader.Close()
		// mimetype MUST be first
		zFilenames := []string{"mimetype"}

		// find all files to be copied
		for _, zFile := range zipReader.File {
			if zFile.Name == zFilenames[0] ||
				zFile.Name == "META-INF/encryption.xml" {
				continue
			}
			zFilenames = append(zFilenames, zFile.Name)
		}

		// Create target file
		filename := fmt.Sprintf("%s.epub", *lcpl.ID)

		archive, err := os.Create(filename)
		if err != nil {
			fmt.Printf("Errore durante la creazione del file %s\n", filename)
			return
		}
		defer archive.Close()
		zipWriter := zip.NewWriter(archive)
		defer zipWriter.Close()

		// init loop vars
		var key []byte
		for i, zFilename := range zFilenames {
			printProgress("Decrypt ", i, len(zFilenames))
			for _, zFile := range zipReader.File {
				// look for zFilename in source zip
				if zFile.Name != zFilename {
					continue
				}
				key = nil
				if slices.Contains(encr_files, zFilename) {
					// encrypted
					key = decryptedContentKey
				}

				err = copyEpubFile(zFile, zipWriter, key)
				if err != nil {
					fmt.Printf("%v\n", err)
					return
				}
			}

		}
		zipWriter.Close()
		archive.Close()
		printProgress("Decrypt ", 1, 1)
		newName := findEpubTitle(filename)
		if newName != nil {
			err = os.Rename(filename, *newName)
			if err == nil {
				filename = *newName
			}
		}
		fmt.Printf("Ok! Scritto il file %s\n", filename)

	} else {
		fmt.Printf("Downloaded something %s\n", *encryptedFile)
	}

}

// Build a title for an epub file, if possible
func findEpubTitle(filename string) *string {
	// open epub
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return nil
	}
	defer reader.Close()

	// look for metadata file
	fencr, err := reader.Open("META-INF/container.xml")
	if err != nil {
		return nil
	}
	xmlbyte, err := io.ReadAll((fencr))
	if err != nil {
		return nil
	}
	fencr.Close()
	var container EpubContainer

	if err := xml.Unmarshal(xmlbyte, &container); err != nil {
		return nil
	}
	rootfile := container.Rootfiles.Rootfile.FullPath
	if container.Rootfiles.Rootfile.FullPath == "" {
		return nil
	}
	// open root file
	fencr, err = reader.Open(rootfile)
	if err != nil {
		return nil
	}
	xmlbyte, err = io.ReadAll((fencr))
	if err != nil {
		return nil
	}
	fencr.Close()
	var epackage EpubPackage

	if err := xml.Unmarshal(xmlbyte, &epackage); err != nil {
		return nil
	}
	title := epackage.Metadata.Title
	author := epackage.Metadata.Creator.Text
	if title == "" || author == "" {

		return nil
	}
	name := fmt.Sprintf("%s - %s", title, author)
	clearChars := func(r rune) rune {
		if strings.ContainsRune("*+/:;<=>?\\[]|.\"", r) {
			return '_'
		}
		if !unicode.IsPrint(r) {
			return '_'
		}
		return r
	}
	name = strings.Map(clearChars, name)
	name = fmt.Sprintf("%s.epub", name)
	return &name

}

func copyEpubFile(zFile *zip.File, zipOut *zip.Writer, decryptKey []byte) error {
	zFilename := zFile.FileHeader.Name

	// copy Header
	newZipFile := &zip.FileHeader{
		Name:           zFile.FileHeader.Name,
		Modified:       zFile.FileHeader.Modified,
		Comment:        zFile.FileHeader.Comment,
		Extra:          zFile.FileHeader.Extra,
		Flags:          zFile.FileHeader.Flags,
		ExternalAttrs:  zFile.FileHeader.ExternalAttrs,
		CreatorVersion: zFile.FileHeader.CreatorVersion,
		NonUTF8:        zFile.NonUTF8,
		Method:         zip.Deflate,
	}
	if zFilename == "mimetype" {
		// mimetype file MUST be stored, not zipped
		newZipFile.Method = zip.Store
	}
	zOut, err := zipOut.CreateHeader(newZipFile)
	if err != nil {
		return fmt.Errorf("errore durante la scrittura dentro lo zip del file %s: %w", zFilename, err)
	}
	// read zipped content
	zIn, err := zFile.Open()
	if err != nil {
		return fmt.Errorf("errore durante la lettura dentro lo zip del file %s: %w", zFilename, err)
	}
	defer zIn.Close()

	if decryptKey != nil {
		encData, err := io.ReadAll(zIn)
		if err != nil {
			return fmt.Errorf("errore durante la lettura dentro lo zip del file %s: %w", zFilename, err)
		}
		decryptData, err := dataDecryptLCP(encData, decryptKey)
		if err != nil {
			return fmt.Errorf("errore durante la decriptazione del file %s: %w", zFilename, err)
		}
		zlibReader := flate.NewReader(bytes.NewReader(decryptData))

		_, err = io.Copy(zOut, zlibReader)
		if err != nil {
			// Not compressed
			zOut.Write(decryptData)
		}
	} else {
		_, err = io.Copy(zOut, zIn)
		if err != nil {
			return fmt.Errorf("errore durante la copia del file %s: %w", zFilename, err)
		}
	}
	return nil
}

// Find a list of filenames encrypted in the ebup
func findEncryptedEbookFilenames(filename string) ([]string, error) {
	// open zip
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return nil, err
	}

	// look for metadata file
	fencr, err := reader.Open("META-INF/encryption.xml")
	if err != nil {
		return nil, err
	}
	defer fencr.Close()
	xmlbyte, err := io.ReadAll((fencr))
	if err != nil {
		return nil, err
	}
	var xencryption XMLEncryption

	if err := xml.Unmarshal(xmlbyte, &xencryption); err != nil {
		return nil, err
	}

	var encrFiles []string
	for _, encdata := range xencryption.EncryptedData {
		if encdata.EncryptionMethod.Algorithm != "http://www.w3.org/2001/04/xmlenc#aes256-cbc" {
			return nil, fmt.Errorf("EncryptionMethod sconosciuto: %s", encdata.EncryptionMethod.Algorithm)
		}

		if encdata.CipherData.CipherReference.URI == "" {
			return nil, fmt.Errorf("CipherReference non trovato")
		}

		encrFiles = append(encrFiles, encdata.CipherData.CipherReference.URI)
	}

	return encrFiles, nil
}

// Print a progress bar
func printProgress(label string, read int, size int) {
	if size < 1 {
		return
	}
	i := 100 * read / size
	fmt.Printf("\r%s progress:   %d%% ", label, i)
	for j := 0; j < i/2; j++ {
		fmt.Print("=")
	}
	if read >= size {
		fmt.Print("\n")
	}
	os.Stdout.Sync()
}

// Download from url and save to filename
func urlRetrieve(url string, filename string) (int, error) {
	if !strings.HasPrefix(url, "https://") {
		return 0, fmt.Errorf("invalid URL: %s", url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	out, err := os.Create(filename)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	size := int(resp.ContentLength)
	read := 0
	buf := make([]byte, 1024*8)

	printProgress("Download", read, size)

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			read += n
			out.Write(buf[:n])
			printProgress("Download", read, size)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return read, err
		}
	}

	if size >= 0 && read < size {
		return read, fmt.Errorf("download incompleto: ho scaricato solo %d di %d byte", read, size)
	}

	return read, nil
}

// Looks into a LCP License and return the downloaded filename
func getPubblication(lcpl LCPL) *string {
	var pubblication *string
	for _, link := range lcpl.Links {
		if link.Rel == "publication" {
			pubblication = &link.HRef
			break
		}
	}
	if pubblication == nil {
		fmt.Println("Download URL non trovata")
		return nil
	}
	filename := fmt.Sprintf("%s.zip", *lcpl.ID)
	if _, err := os.Stat("./" + filename); err == nil {
		// file exists
		printProgress("Download", 1, 1)
	} else if errors.Is(err, os.ErrNotExist) {
		// download
		bread, err := urlRetrieve(*pubblication, filename)
		if err != nil || bread < 1 {
			fmt.Println("Errore con il download")
			return nil
		}

	} else {
		// ???
		fmt.Printf("Non so che fare con: %v\n", err)
		return nil

	}
	return &filename
}

// Check all passphrases for valid a key in the LCP License
func findPassphrase(lcpl LCPL) []byte {
	var decryptedContentKey []byte
	// key_check
	KeyCheck, err := base64.StdEncoding.DecodeString(lcpl.Encryption.UserKey.KeyCheck)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	// encrypted_value
	EncryptedValue, err := base64.StdEncoding.DecodeString(lcpl.Encryption.ContentKey.EncryptedValue)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	for _, passphrase := range passphrases {
		// hash and transform password
		h := sha256.New()
		h.Write([]byte(passphrase))
		passwordTransformed := h.Sum(nil)
		passwordTransformed = transformProfile10(passwordTransformed)
		// let's try and decript key_check with transformed password
		decryptedId, err := dataDecryptLCP(KeyCheck, passwordTransformed)
		if err != nil {
			// fmt.Println(err)
			continue
		}
		if !bytes.Equal(decryptedId, []byte(*lcpl.ID)) {
			continue
		}
		// looks good, decrypt encrypted_value
		decryptedContentKey, err = dataDecryptLCP(EncryptedValue, passwordTransformed)
		if err != nil {
			fmt.Println(err)
			continue
		}
	}
	return decryptedContentKey
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mlol [flags] <license_file>",
	Short: "Scarica da MLOL",
	Long: `Scarica e decripta contenuti a partire da un file
LCP Licence scaricato da MLOL.`,
	Args: cobra.ExactArgs(1),
	Run:  MainMlol,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("keep", "k", false, "non cancellare i file criptati scaricati")
	rootCmd.Flags().BoolP("clear", "c", false, "cancella il file lpcl se tutto è andato bene")
	rootCmd.Flags().StringSliceVarP(&passphrases, "passphrase", "p", []string{}, "una possibile passphrase (è possibile ripetere questa opzione)")
	rootCmd.MarkFlagRequired("passphrase")
}
