package model

import "time"

// Node is a remote agent the master can operate. The master itself is not
// stored here: it is always addressed as "local" and reached over the unix
// socket.
type Node struct {
	BaseModel
	Name        string     `gorm:"not null;unique" json:"name"`
	Addr        string     `json:"addr"`
	Status      string     `json:"status"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	GroupID     uint       `json:"groupID"`
	IsBound     bool       `json:"isBound"`
	IsFavorite  bool       `json:"isFavorite"`
	LastSeenAt  *time.Time `json:"lastSeenAt"`
}

// NodeJoinToken is the short lived secret a fresh agent exchanges for its
// certificate pair. It is single use.
type NodeJoinToken struct {
	BaseModel
	Token     string    `gorm:"not null;unique" json:"token"`
	NodeName  string    `json:"nodeName"`
	Used      bool      `json:"used"`
	ExpiredAt time.Time `json:"expiredAt"`
}
