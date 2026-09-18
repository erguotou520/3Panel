package dto

import "time"

type NodeCreate struct {
	Name        string `json:"name" validate:"required"`
	Addr        string `json:"addr"`
	Description string `json:"description"`
	GroupID     uint   `json:"groupID"`
}

type NodeSearch struct {
	Name string `json:"name"`
}

type NodeDelete struct {
	ID uint `json:"id" validate:"required"`
}

// NodeJoin is what a freshly installed agent posts to redeem its token.
type NodeJoin struct {
	Token   string `json:"token" validate:"required"`
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Port    uint   `json:"port"`
	BaseDir string `json:"baseDir"`
	Version string `json:"version"`
}

// NodeJoinResult is the material the agent persists before switching to node
// mode. RootCrt is the CA it validates incoming client certificates against.
type NodeJoinResult struct {
	Name      string `json:"name"`
	ServerCrt string `json:"serverCrt"`
	ServerKey string `json:"serverKey"`
	RootCrt   string `json:"rootCrt"`
	NodePort  uint   `json:"nodePort"`
}

// NodeJoinCommand is what the UI shows so an operator can enrol a host.
type NodeJoinCommand struct {
	ID        uint      `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	Command   string    `json:"command"`
	ExpiredAt time.Time `json:"expiredAt"`
}

// NodeInfo mirrors the frontend's Setting.NodeItem.
type NodeInfo struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Addr        string `json:"addr"`
	Status      string `json:"status"`
	Version     string `json:"version"`
	Description string `json:"description"`
	GroupID     uint   `json:"groupID"`
	GroupBelong string `json:"groupBelong"`
	IsXpack     bool   `json:"isXpack"`
	IsBound     bool   `json:"isBound"`
	IsFavorite  bool   `json:"isFavorite"`
}
