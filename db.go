package main

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Organization struct {
	ID             int64  `gorm:"primary_key;unique;not null"`
	StableID       string `gorm:"unique"`
	Name           string `gorm:"uniqueIndex:idx_name_provider"`
	Provider       string `gorm:"uniqueIndex:idx_name_provider"`
	ExpiryDuration uint   `gorm:"default:180"`
	EnableMagic    bool   `gorm:"default:false"`
	MagicDnsDomain string
	OverrideLocal  bool `gorm:"default:false"`
	AclPolicy      *ACLPolicy
	NaviDeployKey  string
	NaviDeployPub  string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ACLPolicy represents a Tailscale ACL Policy.
type ACLPolicy struct {
	Groups        Groups        `json:"groups"        yaml:"groups"`
	Hosts         Hosts         `json:"hosts"         yaml:"hosts"`
	TagOwners     TagOwners     `json:"tagOwners"     yaml:"tagOwners"`
	ACLs          []ACL         `json:"acls"          yaml:"acls"`
	Tests         []ACLTest     `json:"tests"         yaml:"tests"`
	AutoApprovers AutoApprovers `json:"autoApprovers" yaml:"autoApprovers"`
	SSHs          []SSH         `json:"ssh"           yaml:"ssh"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action       string   `json:"action" yaml:"action"`
	Protocol     string   `json:"proto"  yaml:"proto"`
	Sources      []string `json:"src"    yaml:"src"`
	Destinations []string `json:"dst"    yaml:"dst"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netip.Prefix

// TagOwners specify what users (users?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	Source string   `json:"src"            yaml:"src"`
	Accept []string `json:"accept"         yaml:"accept"`
	Deny   []string `json:"deny,omitempty" yaml:"deny,omitempty"`
}

// AutoApprovers specify which users (users?), groups or tags have their advertised routes
// or exit node status automatically enabled.
type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"   yaml:"routes"`
	ExitNode []string            `json:"exitNode" yaml:"exitNode"`
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       string   `json:"action"                yaml:"action"`
	Sources      []string `json:"src"                   yaml:"src"`
	Destinations []string `json:"dst"                   yaml:"dst"`
	Users        []string `json:"users"                 yaml:"users"`
	CheckPeriod  string   `json:"checkPeriod,omitempty" yaml:"checkPeriod,omitempty"`
}

type DataPool struct {
	db *gorm.DB
}

func (dp *DataPool) OpenDB() error {
	var log logger.Interface
	log = logger.Default.LogMode(logger.Silent)

	db, err := gorm.Open(
		sqlite.Open(GetFilePath("db.sqlite")+"?_synchronous=1&_journal_mode=WAL"),
		&gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   log,
		},
	)

	db.Exec("PRAGMA foreign_keys=ON")

	// The pure Go SQLite library does not handle locking in
	// the same way as the C based one and we cant use the gorm
	// connection pool as of 2022/02/23.
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxIdleTime(time.Hour)

	if err != nil {
		return err
	}
	dp.db = db

	return nil
}

func (dp *DataPool) InitDB() {
	dp.db.AutoMigrate(&Organization{})
}

func GetAppDirectory() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))

	return path[:index]
}
func GetFilePath(filename string) string {
	dir := GetAppDirectory()
	return filepath.Join(dir, filename)
}
func ReWriteFile(path string, text string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Truncate(0)
	f.Seek(0, 0)
	f.WriteString(text)
	return nil
}

// ACLPolicy struct to json implement
func (a *ACLPolicy) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, a)

	case string:
		return json.Unmarshal([]byte(value), a)

	default:
		return fmt.Errorf("%s: unexpected data type %T", "ErrMachineAddressesInvalid", destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (a ACLPolicy) Value() (driver.Value, error) {
	bytes, err := json.Marshal(a)

	return string(bytes), err
}
func LoadConfig(path string) (*ACLPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	conf := &ACLPolicy{}
	err = json.Unmarshal(body, conf)
	if err != nil {
		return nil, errors.Join(errors.New("Unmarshal Config Failed"), err)
	}
	return conf, nil
}
