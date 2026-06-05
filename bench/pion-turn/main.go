// Minimal pion/turn server for the benchmark matrix.
//
// Implements the same TURN REST credential convention as turna, coturn
// (use-auth-secret) and eturnal (secret): the client sends
// username = "<unix_expiry>:<uid>" and password =
// base64(HMAC-SHA1(secret, username)). One credential setting in the
// load generator therefore works against all four servers.
//
// Build:  cd bench/pion-turn && go build -o ../bin/pion-turn .
// Run:    bench/bin/pion-turn   (defaults match bench/matrix.sh)
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/pion/turn/v4"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "listen/relay IP")
	port := flag.Int("port", 3481, "UDP listen port")
	realm := flag.String("realm", "bench", "auth realm")
	secret := flag.String("secret", "bench-secret", "TURN REST shared secret")
	minPort := flag.Int("min-port", 20000, "relay range start")
	maxPort := flag.Int("max-port", 29999, "relay range end")
	flag.Parse()

	udpListener, err := net.ListenPacket("udp4", *ip+":"+strconv.Itoa(*port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		// REST-style auth: recompute the ephemeral password from the
		// shared secret. Expiry inside the username is not enforced
		// here — this is a bench fixture, not a production server.
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			if !strings.Contains(username, ":") {
				return nil, false
			}
			mac := hmac.New(sha1.New, []byte(*secret))
			mac.Write([]byte(username))
			password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			return turn.GenerateAuthKey(username, realm, password), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: net.ParseIP(*ip),
					Address:      *ip,
					MinPort:      uint16(*minPort),
					MaxPort:      uint16(*maxPort),
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Printf("pion-turn bench server on %s:%d (realm=%s, relay %d-%d)",
		*ip, *port, *realm, *minPort, *maxPort)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	_ = s.Close()
}
