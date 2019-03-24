package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	UUID uuid.UUID                       // UUID = UUID(HMAC(A2K[16:32], username)
	K0 []byte                            // K0 = A2K(password, salt = username, 8 bytes)[:16]
	MyFileUUIDTable map[string]uuid.UUID // A map from filename --> fileHead UUID
	MyFileKeyTable map[string][]byte     // A map from filename --> FileHead master key, used to make
																			 //   the encryption and signature storage keys for that filehead
	SignaturePrivKey userlib.DSSignKey   // Private key for Digital Signatures, for sharing
	AsymmPrivKey userlib.PKEDecKey       // Private key for Asymmetric Encryption, for sharing
}

type FileHead struct {
	NumSegments int;                   // Integer number of segments in this file
	SegmentUUIDTable map[int]uuid.UUID // A map from segment # --> FileSegment UUID
	SegmentKeyTable map[int][]byte     // A map from segment # --> key to decrypt segment
}

// Uploads a []byte to the Datastore, encrypting it with a key and also appending the hash of ciphertext to the end.
func GAESUpload(uuid_u uuid.UUID, plaintext []byte, key []byte) {
	EncKey, _ := userlib.HMACEval(key, []byte("encryptMeOrElse"))
	EncKey = EncKey[:16]
	MacKey, _ := userlib.HMACEval(key, []byte("macAndCheese"))
	MacKey = MacKey[:16]
	cipherText := userlib.SymEnc(EncKey, userlib.RandomBytes(16), plaintext)
	mac, _ := userlib.HMACEval(MacKey, cipherText)
	userlib.DatastoreSet(uuid_u, append(cipherText, mac...))
}

// Downloads the output of GAESUpload from Datastore, checks the hash for tampering, and decrypts.
func GAESFetch(uuid_u uuid.UUID, key []byte) (plaintext []byte, err error) {
	ciphertext, ok := userlib.DatastoreGet(uuid_u)
		if !ok {
			return nil, errors.New("UUID not in Datastore.")
		}

	EncKey, _ := userlib.HMACEval(key, []byte("encryptMeOrElse"))
	EncKey = EncKey[:16]
	MacKey, _ := userlib.HMACEval(key, []byte("macAndCheese"))
	MacKey = MacKey[:16]
	lentext := len(ciphertext)
	MAC := ciphertext[(lentext-64):] // 512 bits -> 16 bytes
	encMessage := ciphertext[:(lentext-64)] // 512 bits -> 16 bytes
	newMac, _ := userlib.HMACEval(MacKey, encMessage)
		if !userlib.HMACEqual(MAC, newMac) {
			return nil, errors.New("Datastore was tampered with.")
		}
	decMessage := userlib.SymDec(EncKey, encMessage)
	return decMessage, nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Username
	userdata.Username = username

	// Initialize Maps
	userdata.MyFileUUIDTable = make(map[string]uuid.UUID)
	userdata.MyFileKeyTable = make(map[string][]byte)

	// K0 + UUID
	K0andUUIDHashKey := userlib.Argon2Key([]byte(password), []byte(username), 32)
	userdata.K0 = K0andUUIDHashKey[:16]
	UUIDHashKey := K0andUUIDHashKey[16:32]
	UUIDMac, _ := userlib.HMACEval(UUIDHashKey, []byte(username))
	userdata.UUID, _ = uuid.FromBytes(UUIDMac[:16])

	// Asymmetric Encryption
	pubEncKey, privEncKey, err1 := userlib.PKEKeyGen()
		if err1 != nil {
			return nil, errors.New("Error while generating Public Keypair!")
		}
	userdata.AsymmPrivKey = privEncKey
	userlib.KeystoreSet(username + "/asym", pubEncKey)

	// Signatures
	privSignKey, pubSignKey, err2 := userlib.DSKeyGen()
		if err2 != nil {
			return nil, errors.New("Error while generating Signature Keypair!")
		}
	userdata.SignaturePrivKey = privSignKey
	userlib.KeystoreSet(username + "/sign", pubSignKey)

	// Upload
	marshalled, _ := json.Marshal(userdata)
	GAESUpload(userdata.UUID, marshalled, userdata.K0)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	tryK0andUUIDHashKey := userlib.Argon2Key([]byte(password), []byte(username), 32)
	tryK0 := tryK0andUUIDHashKey[:16]
	tryUUIDHashKey := tryK0andUUIDHashKey[16:32]
	tryUUIDMac, _ := userlib.HMACEval(tryUUIDHashKey, []byte(username))
	tryUUID, _ := uuid.FromBytes(tryUUIDMac[:16])

	// Try to fetch from Datastore
	fetched, err := GAESFetch(tryUUID, tryK0)
		if err != nil {
			return nil, err
		}

	// Unmarshal bytes -> struct
	err = json.Unmarshal(fetched, userdataptr)
		if err != nil{
			return nil, err
		}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Create a random UUID and key for the filehead
	FileHeadUUID := uuid.New()
	FileHeadMasterKey := userlib.RandomBytes(16) // This key will actually be used to create FileHeadEncryptKey and FileHeadSignatureShareEncryptKey
	FileHeadEncryptKeyOverflow, _ := userlib.HMACEval(FileHeadMasterKey, []byte("GetFileHeadEncryptKey"))
	FileHeadEncryptKey := FileHeadEncryptKeyOverflow[:16]
	var newFileHead FileHead
	newFileHead.NumSegments = 1

	// Create the new #1 segment to hold contents, and upload it
	FileSegmentUUID := uuid.New()
	FileSegmentKey := userlib.RandomBytes(16)
	GAESUpload(FileSegmentUUID, data, FileSegmentKey)

	// Initialize maps in filehead, and put segment #1 into them at mapping for 0
	newFileHead.SegmentUUIDTable = make(map[int]uuid.UUID)
	newFileHead.SegmentKeyTable = make(map[int][]byte)
	newFileHead.SegmentUUIDTable[0] = FileSegmentUUID
	newFileHead.SegmentKeyTable[0] = FileSegmentKey

	// Upload filehead
	marshalledFileHead, _ := json.Marshal(newFileHead)
	GAESUpload(FileHeadUUID, marshalledFileHead, FileHeadEncryptKey)

	// Add filehead to user's file tables
	userdata.MyFileUUIDTable[filename] = FileHeadUUID
	userdata.MyFileKeyTable[filename] = FileHeadMasterKey

	// Upload updated user struct
	marshalledUser, _ := json.Marshal(userdata)
	GAESUpload(userdata.UUID, marshalledUser, userdata.K0)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Get FileHead access details
	fileHeadUUID, ok := userdata.MyFileUUIDTable[filename]
		if !ok {
			return errors.New("File not found in user table.")
		}
	// Get filehead key and from that, deduce the fileHead's encryption key
	fileHeadMasterKey, _ := userdata.MyFileKeyTable[filename] // If it existed in UUID table it exists in key table
	FileHeadEncryptKeyOverflow, _ := userlib.HMACEval(fileHeadMasterKey, []byte("GetFileHeadEncryptKey"))
	fileHeadEncryptKey := FileHeadEncryptKeyOverflow[:16]

	// Fetch FileHead
	var fileHead FileHead
	fetched, err := GAESFetch(fileHeadUUID, fileHeadEncryptKey)
		if err != nil {
			return err
		}
	err = json.Unmarshal(fetched, &fileHead)
		if err != nil {
			return err
		}

	// Create new file segment and upload it with the new data
	newSegmentUUID := uuid.New()
	newSegmentKey := userlib.RandomBytes(16)
	GAESUpload(newSegmentUUID, data, newSegmentKey)

	// Link new file segment to the file head
	fileHead.SegmentUUIDTable[fileHead.NumSegments] = newSegmentUUID
	fileHead.SegmentKeyTable[fileHead.NumSegments] = newSegmentKey
	fileHead.NumSegments += 1

	// Upload updated file head
	marshalledFileHead, _ := json.Marshal(fileHead)
	GAESUpload(fileHeadUUID, marshalledFileHead, fileHeadEncryptKey)
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Get filehead UUID
	fileHeadUUID, ok1 := userdata.MyFileUUIDTable[filename]
		if !ok1 {
			return nil, errors.New("File not found in user table!")
		}

	// Get filehead key and from that, deduce the fileHead's encryption key
	fileHeadMasterKey, _ := userdata.MyFileKeyTable[filename]
	FileHeadEncryptKeyOverflow, _ := userlib.HMACEval(fileHeadMasterKey, []byte("GetFileHeadEncryptKey"))
	fileHeadEncryptKey := FileHeadEncryptKeyOverflow[:16]

	// Get file head and unmarshal it back into a struct
	fileHeadMarshaled, err := GAESFetch(fileHeadUUID, fileHeadEncryptKey)
		if err != nil {
			return nil, err
		}
	var fileHead FileHead
	err = json.Unmarshal(fileHeadMarshaled, &fileHead)
		if err != nil {
			return nil, err
		}

	// Construct the file back
	var currentSegment []byte
	var currentUUID uuid.UUID
	var currentKey []byte
	for i := 0; i < fileHead.NumSegments; i++ {
		currentUUID = fileHead.SegmentUUIDTable[i]
		currentKey = fileHead.SegmentKeyTable[i]
		// No need to unmarshal, file data is never marshalled in the first place
		currentSegment, err = GAESFetch(currentUUID, currentKey)
			if err != nil {
				return nil, err
			}
		data = append(data, currentSegment...)
	}
	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	// Get file head UUID
	fileHeadUUID, ok1 := userdata.MyFileUUIDTable[filename]
		if !ok1 {
			return "", errors.New("File not found in user table!")
		}

	// Get file head key and from that, deduce share key using both people's usernames to encrypt the uploaded signature
	fileHeadMasterKey, _ := userdata.MyFileKeyTable[filename] // If it existed in UUID table it exists in key table
	FileHeadSignatureShareEncryptKeyOverflow, _ := userlib.HMACEval(fileHeadMasterKey, []byte(userdata.Username + recipient)) // sender + recipient
	FileHeadSignatureShareEncryptKey := FileHeadSignatureShareEncryptKeyOverflow[:16]

	// Turn file head UUID into []byte
	bytesForUUID, _ := json.Marshal(fileHeadUUID) //IMPORTANT: MARSHALLED UUIDS ARE 38 BYTES LONG

	// Append: fileheadMasterkey || marshalled(fileheadUUID)
	magicStringUnenc := append(fileHeadMasterKey,bytesForUUID...)

	// Get recipient's public enc key
	hisPubEncKey, ok2 := userlib.KeystoreGet(recipient + "/asym")
		if !ok2 {
			return "", errors.New("Recipient's public encryption key not found!")
		}

	// Create random UUID to store signature in datastore
	signatureUUID := uuid.New()
	signatureUUIDMarshaled, _ :=  json.Marshal(signatureUUID)

	// Append signature UUID to message
	magicStringEnc, err1 := userlib.PKEEnc(hisPubEncKey, append(magicStringUnenc, signatureUUIDMarshaled...))
		if err1 != nil {
			return "", err1
		}

	// Calculate signature on full ENCRYPTED magic string: (fileHeadMasterKey||fileheadUUIDmarshalled||signatureUUIDmarshalled)
	signature, err2 := userlib.DSSign(userdata.SignaturePrivKey, magicStringEnc)
		if err2 != nil {
			return "", err2
		}

	// Upload signature to Datastore with GAEScheme, using FileHeadSignatureShareEncryptKey as key
	GAESUpload(signatureUUID, signature, FileHeadSignatureShareEncryptKey)

	magic_string = string(magicStringEnc)
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	// Get sender's public signing key
	hisPubSignKey, ok1 := userlib.KeystoreGet(sender + "/sign")
		if !ok1 {
			return errors.New("Sender's public signing key not found!")
		}

	// Decrypt magic string using my private asymmetric encryption key
	magicStringEncrypted := []byte(magic_string)
	magicStringDecrypted, err1 := userlib.PKEDec(userdata.AsymmPrivKey, magicStringEncrypted)
		if err1 != nil {
			return err1
		}

	// MAGIC STRING IS (fileHeadMasterKey,16bytes || fileheadUUIDmarshalled,38bytes || signatureUUIDmarshalled,38bytes)
	// Let's get all three components out
	var signatureUUID uuid.UUID
	err2 := json.Unmarshal(magicStringDecrypted[54:], &signatureUUID)
		if err2 != nil {
			return err2
		}
	var newFileHeadUUID uuid.UUID
	err3 := json.Unmarshal(magicStringDecrypted[16:54], &newFileHeadUUID)
		if err3 != nil {
			return err3
		}
	newFileHeadMasterKey := magicStringDecrypted[:16]

	// From newFileHeadMasterKey, deduce share key using both people's usernames to decrypt the uploaded signature
	FileHeadSignatureShareEncryptKeyOverflow, _ := userlib.HMACEval(newFileHeadMasterKey, []byte(sender + userdata.Username)) // sender + recipient
	FileHeadSignatureShareEncryptKey := FileHeadSignatureShareEncryptKeyOverflow[:16]

	// Fetch and verify signature on the magicStringEncrypted
	signature, err4 := GAESFetch(signatureUUID, FileHeadSignatureShareEncryptKey)
		if err4 != nil {
			return errors.New("Temporary signature was lost or corrupted.")
		}
	err5 := userlib.DSVerify(hisPubSignKey, magicStringEncrypted, signature)
		if err5 != nil {
			return errors.New("Unable to verify signature on magic string.")
		}
	userlib.DatastoreDelete(signatureUUID) // If we verified, we can delete that signature from the Datastore

	// If everything's good, let's add the info to our tables.
	userdata.MyFileUUIDTable[filename] = newFileHeadUUID
	userdata.MyFileKeyTable[filename] = newFileHeadMasterKey

	// Upload updated user structure
	marshalledUser, _ := json.Marshal(userdata)
	GAESUpload(userdata.UUID, marshalledUser, userdata.K0)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// *** START: COPIED FROM LOADFILE
	// Get filehead UUID
	fileHeadUUID, ok1 := userdata.MyFileUUIDTable[filename]
		if !ok1 {
			return errors.New("File not found in user table!")
		}

	// Get filehead key
	fileHeadMasterKey, _ := userdata.MyFileKeyTable[filename]
	FileHeadEncryptKeyOverflow, _ := userlib.HMACEval(fileHeadMasterKey, []byte("GetFileHeadEncryptKey"))
	fileHeadEncryptKey := FileHeadEncryptKeyOverflow[:16]

	// Get file head and unmarshal it back into a struct
	fileHeadMarshaled, err := GAESFetch(fileHeadUUID, fileHeadEncryptKey)
		if err != nil {
			return err
		}
	var fileHead FileHead
	err = json.Unmarshal(fileHeadMarshaled, &fileHead)
		if err != nil {
			return err
		}
	// *** END: COPIED FROM LOADFILE

	newFileHeadUUID := uuid.New() // Generate new UUID for the fileHead to be moved to
	newFileHeadMasterKey := userlib.RandomBytes(16) // Generate new key for the file head
	newFileHeadEncryptKeyOverflow, _ := userlib.HMACEval(newFileHeadMasterKey, []byte("GetFileHeadEncryptKey"))
	newfileHeadEncryptKey := newFileHeadEncryptKeyOverflow[:16]

	// Upload filehead to new location
	marshalledFileHead, _ := json.Marshal(fileHead)
	GAESUpload(newFileHeadUUID, marshalledFileHead, newfileHeadEncryptKey)

	// If new location upload successful, we delete file head from old location
	// so users who now have no access just have a UUID that doesn't exist anymore
	userlib.DatastoreDelete(fileHeadUUID)

	// Update location and key for filehead in user struct
	userdata.MyFileUUIDTable[filename] = newFileHeadUUID
	userdata.MyFileKeyTable[filename] = newFileHeadMasterKey

	// Upload updated user struct
	marshalledUser, _ := json.Marshal(userdata)
	GAESUpload(userdata.UUID, marshalledUser, userdata.K0)

	return
}
