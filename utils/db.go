package utils

import (
	"database/sql"
	"log"
)

type Users struct {
	// mu sync.Mutex
	db *sql.DB
}

const dbFile string = "flextool.db"

const create string = `
  CREATE TABLE IF NOT EXISTS users (
  id INTEGER NOT NULL PRIMARY KEY,
  username TEXT,
  client_ip TEXT
  );`

// UsersDb creates a sqlite database with a clients table and schema if the file does not already exist
func UsersDb() (*Users, error) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(create); err != nil {
		return nil, err
	}
	return &Users{
		db: db,
	}, nil
}

// DeleteAllUsers removes all user records from the db
func (c *Users) DeleteAllUsers() error {
	_, err := c.db.Exec("DELETE FROM users")
	if err != nil {
		return err
	}

	return nil
}

// Insert adds a user record to the db
func (c *Users) Insert(activity VpnRouteRow) (int, error) {
	res, err := c.db.Exec("INSERT INTO users (username, client_ip) VALUES(?,?);", activity.Name, activity.IP)
	if err != nil {
		return 0, err
	}

	var id int64
	if id, err = res.LastInsertId(); err != nil {
		return 0, err
	}
	return int(id), nil
}

// GetUserIpAddresses returns the ip address of every user record in the db
func (c *Users) GetUserIpAddresses() ([]string, error) {
	rows, err := c.db.Query("SELECT client_ip from users")
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var client_ip_list []string

	for rows.Next() {
		var client_ip string
		err = rows.Scan(&client_ip)
		if err != nil {
			log.Fatal(err)
		}
		client_ip_list = append(client_ip_list, client_ip)
	}

	return client_ip_list, nil
}
