package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/nweaver/cs161-p2/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)


func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	someUsefulThings()
	//userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}

// OUR TESTS

func TestStoreAppendLoad(t *testing.T) {
	// Create user alice
	user, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", user)

	// Initialize testfile
	filename := "testfile"
	data := []byte("testing123")

	// Check StoreFile
	user.StoreFile(filename, data)

	// Check LoadFile
	load, err := user.LoadFile(filename)
	if err != nil {
		t.Error("Failed to upload and download", err)
	}
	if !reflect.DeepEqual(data, load) {
		t.Error("Downloaded file is not the same", data, load)
	}

	// Check AppendFile
	user.AppendFile(filename, data)
	load, err = user.LoadFile(filename)
	if err != nil {
		t.Error("Failed to reload data", err)
	}
	data = []byte("testing123testing123")
	if !reflect.DeepEqual(data, load) {
		t.Error("Downloaded file is not the same", data, load)
	}
}

func TestAppendExtra(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v := []byte("Testing...Testing..")
	u.StoreFile("fileOne", v)
	v1 := []byte(" Append!")
	u.AppendFile("fileOne", v1)
	v2 := []byte(" Append again!")
	u.StoreFile("fileTwo", v)
	u.AppendFile("fileOne", v2)
	v3 := []byte(" Append finally!")
	u.AppendFile("fileOne", v3)

	f1 := append(v, v1...)
	f1 = append(f1, v2...)
	f1 = append(f1, v3...)
	actualF1, err := u.LoadFile("fileOne")
	if err != nil {
		t.Error("Failed to load", err)
	}
	if !reflect.DeepEqual(f1, actualF1) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShareAppendWith3Users(t *testing.T) {
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	bob, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload bob", err)
	}
	// Create 3rd user Eve
	eve, err := InitUser("eve", "fubar")
	if err != nil {
		t.Error("Failed to initialize eve", err)
	}

	alice.StoreFile("TestShareAppend", []byte("This is a file shared then got appended."))

	// Alice shares with Bob
	msgid, err := alice.ShareFile("TestShareAppend", "bob")
		if err != nil {
			t.Error("Alice failed to share the a file", err)
		}
	err = bob.ReceiveFile("TestShareAppend2", "alice", msgid)
		if err != nil {
			t.Error("Bob failed to receive the share message", err)
		}

	// Bob shares with Eve
	msgid, err = bob.ShareFile("TestShareAppend2", "eve")
		if err != nil {
			t.Error("Bob failed to share the a file", err)
		}
	err = eve.ReceiveFile("TestShareAppend3", "bob", msgid)
		if err != nil {
			t.Error("Eve failed to receive the share message", err)
		}

	eve.AppendFile("TestShareAppend3", []byte("This is the appended message."))

	aliceVersion, err := alice.LoadFile("TestShareAppend")
		if err != nil {
			t.Error("Alice failed to download the file after sharing", err)
		}
	bobVersion, err := bob.LoadFile("TestShareAppend2")
		if err != nil {
			t.Error("Bob failed to download the file after sharing", err)
		}
	eveVersion, err := eve.LoadFile("TestShareAppend3")
		if err != nil {
			t.Error("Eve failed to download the file after sharing", err)
		}
	if !reflect.DeepEqual(aliceVersion, eveVersion) {
		t.Error("Shared file is not the same", aliceVersion, eveVersion)
	}
	if !reflect.DeepEqual(aliceVersion, bobVersion) {
		t.Error("Shared file is not the same", aliceVersion, bobVersion)
	}
}

func TestAppendShare(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload bob", err)
	}

	u1.StoreFile("TestAppendShare", []byte("This is a file shared then got appended."))
	u1.AppendFile("TestAppendShare", []byte("This is the appended message."))

	msgid, err := u1.ShareFile("TestAppendShare", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("TestAppendShare2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v1, err := u1.LoadFile("TestAppendShare")
	v2, err := u2.LoadFile("TestAppendShare2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is not the same", v1, v2)
	}
}

func TestAppendShareAppend(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload bob", err)
	}

	var v, v1, v2 []byte
	var msgid string

	v = []byte("This is a file shared then got appended.")
	u1.StoreFile("fileAppendShared", v)

	msgid, err = u1.ShareFile("fileAppendShared", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("VaibhavAndSai", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v1 = []byte("This is the appended message.")
	u2.AppendFile("VaibhavAndSai", v1)

	v3, err := u1.LoadFile("fileAppendShared")
	v2, err = u2.LoadFile("VaibhavAndSai")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v3, v2) {
		t.Error("Shared file is not the same", v3, v2)
	}
}

func TestRevokeByOwner(t *testing.T) {
	// Get user alice
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}
	// Get user bob
	bob, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}
	// Get user eve
	eve, err := GetUser("eve", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}

	// Alice creates file
	filename := "test"
	data := []byte("testing123")
	alice.StoreFile(filename, data)

	// Share the file with bob and eve
	msgid, err := alice.ShareFile(filename, "bob")
	bob.ReceiveFile(filename, "alice", msgid)
	msgid, err = alice.ShareFile(filename, "eve")
	eve.ReceiveFile(filename, "alice", msgid)

	// Alice revokes file
	err = alice.RevokeFile(filename)
	if err != nil {
		t.Error("RevokeFile failed under correct conditions.", err)
	}

	// Check that alice still has access to file
	_, err = alice.LoadFile(filename)
	if err != nil {
		t.Error("Alice can't load the file she revoked from others.", err)
	}

	// But bob and eve do not
	_, err = bob.LoadFile(filename)
		if err == nil {
			t.Error("Bob loaded the file even after Alice revoked access.")
		}
	_, err = eve.LoadFile(filename)
		if err == nil {
			t.Error("Eve loaded the file even after Alice revoked access.")
		}
}

func TestRevokeByRecipient(t *testing.T) {
	// Get user alice
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}
	// Get user bob
	bob, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}
	// Get user eve
	eve, err := GetUser("eve", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}

	// Alice creates file
	alice.StoreFile("file1", []byte("testing123"))

	// Share the file with bob and eve
	msgid, err := alice.ShareFile("file1", "bob")
	bob.ReceiveFile("file2", "alice", msgid)
	msgid, err = alice.ShareFile("file1", "eve")
	eve.ReceiveFile("file3", "alice", msgid)

	// Eve revokes file
	err = eve.RevokeFile("file3")
		if err != nil {
			t.Error("RevokeFile failed under correct conditions.", err)
		}

	// Check that eve still has access to file
	_, err = eve.LoadFile("file3")
		if err != nil {
			t.Error("Eve can't load the file she revoked from others.", err)
		}

	// But bob and alice does not
	_, err = bob.LoadFile("file2")
		if err == nil {
			t.Error("Bob loaded the file even after Eve revoked access.")
		}

	_, err = alice.LoadFile("file1")
		if err == nil {
			t.Error("Alice loaded the file even after Eve revoked access.")
		}
}
