package ftpproxy

import (
	"errors"
	"fmt"
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
func pipeData(log *slog.Logger, clientSide, serverSide net.Conn) (up, down int64, err error) {
	upDone := make(chan struct{})
	downDone := make(chan struct{})
	var upErr, downErr error

	// client -> server (upload)
	go func() {
		n, e := copyStream(serverSide, clientSide, "upload")
		up = n
		upErr = e
		log.Debug("upload copy done", "bytes", n, "err", e)
		// Release the paired download reader, then half-close to the server.
		serverSide.SetReadDeadline(time.Now())
		closeWrite(serverSide)
		close(upDone)
	}()

	// server -> client (download)
	go func() {
		n, e := copyStream(clientSide, serverSide, "download")
		down = n
		downErr = e
		log.Debug("download copy done", "bytes", n, "err", e)
		// Release the paired upload reader, then half-close to the client
		// so it sees EOF on the data connection.
		clientSide.SetReadDeadline(time.Now())
		closeWrite(clientSide)
		close(downDone)
	}()

	<-upDone
	<-downDone
	// On a healthy transfer at most one direction sees a real error: the
	// other is either EOF or a deadline release we set ourselves. Report
	// the download error first, it is the one that kills a RETR.
	if downErr != nil {
		return up, down, downErr
	}
	return up, down, upErr
}

// copyStream copies with a fixed buffer in userspace. Deliberately avoids
// io.Copy's sendfile/splice fast paths: predictable behaviour on half-closed
// sockets and constant memory regardless of file size (up to terabytes).
// A read deadline error is treated as a clean end of stream: pipeData uses
// deadlines only to release paired blocked reads.
//
// Real errors are tagged with direction and phase so the log says who broke
// the transfer: "read" fails when the source (FTP server on a RETR) resets,
// "write" fails when the sink (the client on a RETR) goes away.
func copyStream(dst, src net.Conn, dir string) (int64, error) {
	const chunk = 256 << 10
	buf := make([]byte, chunk)
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			total += int64(nw)
			if werr != nil {
				return total, fmt.Errorf("%s write: %w", dir, werr)
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
		return total, fmt.Errorf("%s read: %w", dir, rerr)
	}
}

// closeWrite half-closes a TCP socket so FIN propagates but reads stay open.
func closeWrite(c net.Conn) error {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return c.Close()
}
