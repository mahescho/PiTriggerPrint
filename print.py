#!/usr/bin/env python
# coding: utf-8

import argparse
import os
import sys
import time
import atexit
import logging
import signal
from threading import Timer
import wiringpi

PRINTCMD="/usr/local/bin/PrintCmd.sh"
COPYCMD="/usr/local/bin/CopyCmd.sh"
COPYINTERVAL=300.0

logger = logging.getLogger('print')
hdlr = logging.FileHandler('/var/log/print.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 

class Daemon(object):
    """
    A generic daemon class.
    Usage: subclass the Daemon class and override the run() method
    """

    def __init__(self, pidfile, stdin='/dev/null',
                 stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced 
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        # Do first fork
        self.fork()

        # Decouple from parent environment
        self.dettach_env()

        # Do second fork
        self.fork()

        # Flush standart file descriptors
        sys.stdout.flush()
        sys.stderr.flush()

        # 
        self.attach_stream('stdin', mode='r')
        self.attach_stream('stdout', mode='a+')
        self.attach_stream('stderr', mode='a+')
       
        # write pidfile
        self.create_pidfile()

    def attach_stream(self, name, mode):
        """
        Replaces the stream with new one
        """
        stream = open(getattr(self, name), mode)
        os.dup2(stream.fileno(), getattr(sys, name).fileno())

    def dettach_env(self):
        os.chdir("/")
        os.setsid()
        os.umask(0)

    def fork(self):
        """
        Spawn the child process
        """
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("Fork failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

    def create_pidfile(self):
        atexit.register(self.delpid)
        pid = str(os.getpid())
        open(self.pidfile,'w+').write("%s\n" % pid)

    def delpid(self):
        """
        Removes the pidfile on process exit
        """
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        pid = self.get_pid()

        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def get_pid(self):
        """
        Returns the PID from pidfile
        """
        try:
            pf = open(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except (IOError, TypeError):
            pid = None
        return pid

    def stop(self, silent=False):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        pid = self.get_pid()

        if not pid:
            if not silent:
                message = "pidfile %s does not exist. Daemon not running?\n"
                sys.stderr.write(message % self.pidfile)
            return # not an error in a restart

        # Try killing the daemon process    
        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                sys.stdout.write(str(err))
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop(silent=True)
        self.start()

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
        raise NotImplementedError


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False



def do_copy():
    logger.info("command: " + COPYCMD) 
    os.system(COPYCMD)

class MyDaemon(Daemon):
    def run(self):
        logger.error("Daemon started") 

        do_copy()
        RepeatedTimer(COPYINTERVAL, do_copy)

        wiringpi.wiringPiSetupGpio()
        wiringpi.pinMode(17, 0)

        state=0
        while True:
            s = wiringpi.digitalRead(17)
            logger.debug(str(s)) 
            if (s <> state):
                state = s
                if (state == 1):
                    logger.info("command: " + PRINTCMD) 
                    os.system(PRINTCMD)
            time.sleep(0.1)


def main():
    """
    The application entry point
    """
    parser = argparse.ArgumentParser(
        description='File Prtinter',
    )

    parser.add_argument('operation',
                    metavar='OPERATION',
                    type=str,
                    help='Commands: start, stop, restart, status',
                    choices=['start', 'stop', 'restart', 'status'])
    parser.add_argument("-c", "--copyinterval", dest="copyinterval", type=int, help="Interval for copy command, defautl 300 sekonds", default=300)
    parser.add_argument("-l", "--loglevel", 
                    dest="loglevel", 
                    type=str, help="Logleve: info, warn, error, debug", 
                    default="error", 
                    choices=['info','warn','error','debug'] )

    args = parser.parse_args()
    operation = args.operation
    COPYINTERVAL = args.copyinterval

    if (args.loglevel == "info"):
        logger.setLevel(logging.INFO)
    elif (args.loglevel == "warn"):
        logger.setLevel(logging.WARN)
    elif (args.loglevel == "error"):
        logger.setLevel(logging.ERROR)
    elif (args.loglevel == "debug"):
        logger.setLevel(logging.DEBUG)


    # Daemon
    daemon = MyDaemon('/var/run/print.pid')

    if operation == 'start':
        print("Starting daemon")
        daemon.start()
        pid = daemon.get_pid()

        if not pid:
            print("Unable run daemon")
        else:
            print("Daemon is running [PID=%d]" % pid)

    elif operation == 'stop':
        print("Stoping daemon")
        daemon.stop()
        logger.error("Daemon stoped") 

    elif operation == 'restart':
        print("Restarting daemon")
        daemon.restart()
        logger.error("Daemon restarted") 
    elif operation == 'status':
        print("Viewing daemon status")
        pid = daemon.get_pid()

        if not pid:
            print("Daemon isn't running ;)")
        else:
            print("Daemon is running [PID=%d]" % pid)

    sys.exit(0)

if __name__ == '__main__':
    main()
