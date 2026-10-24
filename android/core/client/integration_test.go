package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/mux"
	"github.com/kankipro/klink/internal/obfuscation"
	serverSession "github.com/kankipro/klink/internal/session"
	"github.com/kankipro/klink/internal/store"
	baseTransport "github.com/kankipro/klink/internal/transport"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

func TestRealServerTCPUDPRekeyAndMigration(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	clientKey, _ := kcrypto.GenerateKey()
	serverKey, _ := kcrypto.GenerateKey()
	user := &store.User{Name: "android", PublicKey: base64.StdEncoding.EncodeToString(clientKey.Public[:]),
		Token: "android-token", Enabled: true, DeviceLimit: 2}
	if err := db.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	profile := obfuscation.Random{}
	// Same wiring as cmd/server: loopback targets are allowed only because the
	// test echo servers run on 127.0.0.1 (the production policy blocks them).
	manager, err := serverSession.NewManager(serverSession.Config{ServerKey: serverKey, Store: db, Obfuscation: profile,
		RekeyInterval: time.Hour, OnSession: func(s *serverSession.Session) {
			m := mux.NewWithPolicy(s, mux.Policy{AllowLoopback: true})
			s.SetHandlers(m.HandleFrame, m.Close)
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	udpListener, err := baseTransport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	go udpListener.Serve(4, func(p baseTransport.Packet) { manager.HandlePacket(udpListener, p) })
	tcpListener, err := baseTransport.ListenTCPHandler("127.0.0.1:0", kcrypto.Prologue, manager.HandlePacket)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()

	tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go func() {
		for {
			conn, err := tcpEcho.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(buffer[:n], addr)
		}
	}()

	cfg := Config{Version: 1, SessionIDBits: 128, Name: "integration",
		ClientPrivateKey: clientKey.PrivateBase64(), ClientPublicKey: clientKey.PublicBase64(),
		ServerPublicKey: serverKey.PublicBase64(), Obfuscation: "random", RekeyIntervalSeconds: 900, RekeyPackets: 1,
		Transports: []TransportConfig{{Network: "udp", Endpoint: udpListener.LocalAddr().String()},
			{Network: "tcp", Endpoint: tcpListener.LocalAddr().String()}}}
	canonical, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := Connect(ctx, string(canonical))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if session.Network() != "udp" || session.State() != StateConnected {
		t.Fatalf("unexpected initial state")
	}
	proxy := &Proxy{Session: session}
	tcpAddr := tcpEcho.Addr().(*net.TCPAddr)
	stream, err := proxy.DialContext(ctx, &M.Metadata{Network: M.TCP, DstIP: netip.MustParseAddr(tcpAddr.IP.String()), DstPort: uint16(tcpAddr.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write([]byte("before-migration")); err != nil {
		t.Fatal(err)
	}
	assertReadString(t, stream, "before-migration")

	migrateCtx, migrateCancel := context.WithTimeout(context.Background(), 8*time.Second)
	if err := session.tryMigrate(migrateCtx, "tcp"); err != nil {
		t.Fatal(err)
	}
	migrateCancel()
	if session.Network() != "tcp" {
		t.Fatal("transport did not migrate")
	}
	if _, err := stream.Write([]byte("after-migration")); err != nil {
		t.Fatal(err)
	}
	assertReadString(t, stream, "after-migration")

	udpAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	packet, err := proxy.DialUDP(&M.Metadata{Network: M.UDP, DstIP: netip.MustParseAddr(udpAddr.IP.String()), DstPort: uint16(udpAddr.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := packet.WriteTo([]byte("udp-through-klink"), nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, _, err := packet.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "udp-through-klink" {
		t.Fatalf("UDP echo: %q %v", buffer[:n], err)
	}
	if !session.probeCurrent() {
		t.Fatal("encrypted ping/pong failed")
	}
}

func assertReadString(t *testing.T, conn net.Conn, expected string) {
	t.Helper()
	buffer := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != expected {
		t.Fatalf("got %q want %q", buffer, expected)
	}
}
