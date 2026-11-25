package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const controlSocket = "run.sock"

func lockDirectory() (*os.File, error) {
	const name = "run.lock"
	fd, err := syscall.Open(name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		_ = file.Close()
		return nil, errors.New("probe lock must be a private file owned by the current user")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errLocked
		}
		return nil, err
	}
	return file, nil
}

func verifySocket() error {
	info, err := os.Lstat(controlSocket)
	if errors.Is(err, os.ErrNotExist) {
		return errDown
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || !ownedByCurrentUser(info) {
		return errors.New("control socket is not owned by this probe user")
	}
	return nil
}

func run(parent context.Context) error {
	lock, err := lockDirectory()
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("load probe credentials: %w", err)
	}
	if !state.Enrolled {
		return errors.New("probe registration is incomplete")
	}
	if err := verifySocket(); err == nil {
		if err := os.Remove(controlSocket); err != nil {
			return err
		}
	} else if !errors.Is(err, errDown) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlSocket, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(controlSocket, 0o600); err != nil {
		_ = listener.Close()
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	routeDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		runRoutes(ctx, state)
	}()
	defer func() {
		cancel()
		<-routeDone
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveControl(listener, cancel)
	}()
	defer func() {
		_ = listener.Close()
		<-done
	}()
	return runMonitor(ctx, newManagerClient(state))
}

func serveControl(listener *net.UnixListener, cancel context.CancelFunc) {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		command, err := bufio.NewReaderSize(conn, 32).ReadSlice('\n')
		if err == nil {
			switch string(command) {
			case "status\n":
				_, _ = conn.Write([]byte("running\n"))
			case "stop\n":
				_, _ = conn.Write([]byte("stopping\n"))
				cancel()
			}
		}
		_ = conn.Close()
	}
}

func control(ctx context.Context, command string) error {
	if err := verifySocket(); err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "unix", controlSocket)
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
		return errDown
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := fmt.Fprintln(conn, command); err != nil {
		return err
	}
	response, err := bufio.NewReaderSize(conn, 32).ReadSlice('\n')
	if err != nil {
		return err
	}
	if command == "status" && string(response) == "running\n" || command == "stop" && string(response) == "stopping\n" {
		return nil
	}
	return errors.New("unexpected response from probe control socket")
}

func stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	requested := false
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		lock, err := lockDirectory()
		if err == nil {
			return lock.Close()
		}
		if !errors.Is(err, errLocked) {
			return err
		}
		if !requested {
			err := control(ctx, "stop")
			if err != nil && !errors.Is(err, errDown) {
				return err
			}
			requested = err == nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for probe to stop: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
