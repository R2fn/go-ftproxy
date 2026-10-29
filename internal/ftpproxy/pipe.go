package ftpproxy

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"time"
)

// pipeData streams one FTP data transfer: clientSide is the connection to
// the client, serverSide the connection to the upstream server. File data
// is streamed with fixed buffers; nothing is buffered on disk.
//
// Windows IOCP detail: TCPConn.CloseWrite on a socket whose peer pair has a
// still-pending Read can delay FIN propagation on that socket pair. FTP
// data channels are unidirectional per command (RETR or STOR, never both),
// so when one direction finishes we immediately release the *other* side's
// blocked read with an expired deadline before half-closing. This keeps FIN
// propagation prompt on every platform.
func pipeData(log *slog.Logger, clientSide, serverSide net.Conn) (up, down int64) {
	upDone := make(chan struct{})
	downDone := make(chan struct{})

	// client -> server (upload)
	go func() {
		n, err := copyStream(serverSide, clientSide)
		up = n
		log.Debug("upload copy done", "bytes", n, "err", err)
		// Release the paired download reader, then half-close to the server.
		serverSide.SetReadDeadline(time.Now())
		closeWrite(serverSide)
		close(upDone)
	}()

	// server -> client (download)
	go func() {
		n, err := copyStream(clientSide, serverSide)
		down = n
		log.Debug("download copy done", "bytes", n, "err", err)
		// Release the paired upload reader, then half-close to the client
		// so it sees EOF on the data connection.
		clientSide.SetReadDeadline(time.Now())
		closeWrite(clientSide)
		close(downDone)
	}()

	<-upDone
	<-downDone
	return up, down
}

// copyStream copies with a fixed buffer in userspace. Deliberately avoids
// io.Copy's sendfile/splice fast paths: predictable behaviour on half-closed
// sockets and constant memory regardless of file size (up to terabytes).
// A read deadline error is treated as a clean end of stream: pipeData uses
// deadlines only to release paired blocked reads.
func copyStream(dst, src net.Conn) (int64, error) {
	const chunk = 256 << 10
	buf := make([]byte, chunk)
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			total += int64(nw)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == nil {
			continue
		}
		if rerr == io.EOF {
			return total, nil
		}
		var nerr net.Error
		if errors.As(rerr, &nerr) && nerr.Timeout() {
			return total, nil
		}
		return total, rerr
	}
}

// closeWrite half-closes a TCP socket so FIN propagates but reads stay open.
func closeWrite(c net.Conn) error {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return c.Close()
}
