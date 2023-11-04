#!/usr/bin/python3
# -*- coding: utf-8 -*-
prog_ver = 'WSVPN VPN Websocket Proxy v1.12'
prog_cpy = 'Copyright (c) 2017-2023 Matej Kovacic, Gasper Zejn, Matjaz Rihtar'
import sys, os, re
import ntpath, argparse
import traceback
import logging

import signal, ssl
import socket, platform, psutil
from subprocess import PIPE, STDOUT
try:
  import queue
except ImportError:
  import Queue as queue
from threading import Thread, Timer

from OpenSSL import crypto, SSL
from binascii import hexlify
from tornado import gen, web, ioloop, iostream, websocket
from tornado.concurrent import Future
from tornado.httpserver import HTTPServer
from tornado.tcpserver import TCPServer
from tornado.httpclient import HTTPRequest
from tornado.tcpclient import TCPClient

msgbuf_len = 65536 # max message buffer length
dtext_len = 256    # max debug text length
closing = False

wsa_errors = {
  '10004': '[The operation was interrupted]',
  '10009': '[A bad file handle was passed]',
  '10013': '[Permission denied]',
  '10014': '[A fault occurred on the network]',
  '10022': '[An invalid operation was attempted]',
  '10035': '[The socket operation would block]',
  '10036': '[A blocking operation is already in progress]',
  '10048': '[The network address is in use]',
  '10054': '[The connection has been reset]',
  '10058': '[The network has been shut down]',
  '10060': '[The operation timed out]',
  '10061': '[Connection refused]',
  '10063': '[The name is too long]',
  '10064': '[The host is down]',
  '10065': '[The host is unreachable]'
}

# =============================================================================
def dump(obj, all=False, detailed=False):
  sys.stderr.write('-----------------------------------\n')
  sys.stderr.write('obj.type = {}\n'.format(type(obj)))
  for attr in dir(obj):
    try:
      value = getattr(obj, attr)
      if not all and str(attr).startswith('_'):
        continue
      else:
        sys.stderr.write('obj.{} = {}\n'.format(attr, value))
        if detailed and str(value).startswith('<'):
          sys.stderr.write('  '); n = 0
          for oattr in dir(value):
            if n > 0: sys.stderr.write(' ')
            sys.stderr.write('{}'.format(oattr)); n += 1
          sys.stderr.write('\n')
    except: pass
# dump

# -----------------------------------------------------------------------------
def ntdirname(path):
  try:
    head, tail = ntpath.split(path)
    if tail == '.' or tail == '..':
      path += os.sep
      head, tail = ntpath.split(path)
    dirname = head or ntpath.dirname(head)
  except: dirname = '.'
  if dirname == '':
    dirname = '.'
  if not dirname.endswith(os.sep):
    dirname += os.sep
  return dirname
# ntdirname

def ntbasename(path):
  try:
    head, tail = ntpath.split(path)
    basename = tail or ntpath.basename(head)
  except: basename = ''
  if basename == '.' or basename == '..':
    basename = ''
  return basename
# ntbasename

# -----------------------------------------------------------------------------
def obj2asc(obj):
# ascii: v >= 0x20 and v < 0x7F
# latin: v >= 0xA0 and v <= 0xFF
  try:
    res = ''
    for c in obj:
      v = ord(c)
      if v > 0xff:
        v1 = (v >> 8) & 0xFF
        if v1 >= 0x20 and v1 < 0x7F:
          res += chr(v1)
        else:
          res += '.'
        v = v & 0xFF
      if v >= 0x20 and v < 0x7F:
        res += chr(v)
      else:
        res += '.'
  except:
    res = obj
  return res
# obj2asc

# -----------------------------------------------------------------------------
def sub_error(f_subr):
  exc_type, exc_obj, exc_tb = sys.exc_info()
  exc = traceback.format_exception_only(exc_type, exc_obj)
  #f_name = os.path.basename(__file__)
  errmsg = '{}({}): {}'.format(f_subr, exc_tb.tb_lineno, exc[-1].strip())
  try:
    m = re.search(r'\[Errno (?P<errno>\d+)\]', errmsg, re.IGNORECASE)
    if m:
      errno = m.group('errno')
      if errno in wsa_errors:
        errmsg = re.sub('\s*Unknown error', '', errmsg)
        errmsg = re.sub(r'\[Errno \d+\]', wsa_errors[errno], errmsg)
  except: pass
  return errmsg
# sub_error

# =============================================================================
def signal_handler(signum, frame):
  global closing
  log.warning('Signal {} received, exiting...'.format(signum))
  closing = True
# signal_handler

def try_exit():
  if closing:
    ioloop.IOLoop.current().stop()
    if route_ip is not None:
      rc, out = delete_route(route_ip)
      if rc != 0:
        log.error(out.strip())
    log.info('Exit success')
# try_exit

# =============================================================================
class StreamToLogger(object):
  def __init__(self, logger, log_level=logging.INFO):
    self.logger = logger
    self.log_level = log_level
    self.linebuf = ''
    self.file = None
    for handler in logging.getLogger().handlers:
      if isinstance(handler, logging.StreamHandler):
        self.file = handler.stream
      elif isinstance(handler, logging.FileHandler):
        self.file = handler.stream

  def write(self, linebuf):
    for line in linebuf.rstrip().splitlines():
      self.logger.log(self.log_level, line.rstrip())

  def fileno(self):
    return self.file.fileno()

  def flush(self):
    self.file.flush()

  def close(self):
    self.file.close()
# StreamToLogger

# =============================================================================
def enq_output(pipe, queue):
  try:
    for line in iter(pipe.readline, ''):
      queue.put(line)
    pipe.close()
  except: pass
  finally:
    queue.put(None)
# enq_output

# -----------------------------------------------------------------------------
def run_cmd(args, timeout=0):
  try:
    cmd = ' '.join(args)
    log.info('Running cmd: {}'.format(cmd))

    if timeout < 0: # start and forget
      #p = psutil.Popen(cmd, shell=True)
      p = psutil.Popen(args, stdout=sys.stdout, stderr=STDOUT)
      return p.pid, 0, ''

    # start and wait
    #p = psutil.Popen(cmd, shell=True)
    p = psutil.Popen(args, stdout=PIPE, stderr=STDOUT, text=True)

    q = queue.Queue()
    qt = Thread(target=enq_output, args=(p.stdout, q))
    qt.start()

    if timeout == 0: # wait until finished
      timeout = 2^31

    t = Timer(timeout, p.terminate)
    output = ''
    try:
      t.start()
      while True:
        try:
          line = q.get(timeout=0.1)
          if line is None:
            break
          if debug:
            dtext = obj2asc(line).decode('utf-8')
            dtext = dtext[:dtext_len] + (dtext[dtext_len:] and '...')
            log.debug('Cmd >> {!r}'.format(dtext))
          output += line
        except queue.Empty: pass
    finally:
      t.cancel()

    qt.join()
    p.wait() # normal or terminated exit
  except:
    errmsg = sub_error(sys._getframe().f_code.co_name)
    log.critical(errmsg)
    return 0, -1, ''

  return p.pid, p.returncode, output
# run_cmd

# =============================================================================
def set_route(ip):
  ipv6 = ':' in ip
  os = platform.system()
  if os == 'Windows':
    args = ['route', 'print']
    pid, rc, out = run_cmd(args)

    gw_ip = ''
    for line in out.splitlines():
      if len(line) == 0:
        continue
      param = line.split()
      if len(param) > 3:
        if ipv6:
          if param[2] == '::/0':
            gw_ip = param[3]
            break
        else:
          if param[0] == '0.0.0.0':
            gw_ip = param[2]
            break

    # route add <ip>/<mask> <gw_ip>
    args = ['route', 'add']
    if ipv6:
      args.append('{}/127'.format(ip))
    else:
      args.append('{}/32'.format(ip))
    args.append('{}'.format(gw_ip))
    pid, rc, out = run_cmd(args)

    for line in out.splitlines():
      if re.search(r'failed:', line, re.IGNORECASE):
        rc = 1

  elif os == 'Linux':
    args = ['ip', 'route']
    pid, rc, out = run_cmd(args)

    gw_ip = ''
    for line in out.splitlines():
      if len(line) == 0:
        continue
      param = line.split()
      if param[0] == 'default':
        gw_ip = param[2]
        break

    # route add <ip> via <gw_ip>
    args = ['ip', 'route', 'add']
    args.append('{}'.format(ip))
    args += ['via']
    args.append('{}'.format(gw_ip))
    pid, rc, out = run_cmd(args)

  elif os == 'Darwin': # MacOS
    args = ['netstat', '-rn']
    pid, rc, out = run_cmd(args)

    gw_ip = ''
    for line in out.splitlines():
      if len(line) == 0:
        continue
      param = line.split()
      if len(param) > 1 and param[0] == 'default':
        if ipv6 and ':' in param[1]:
          gw_ip = param[1]
          break
        else:
          gw_ip = param[1]
          break

    # route add [-inet6] <ip>/<mask> <gw_ip>
    args = ['route', 'add']
    if ipv6:
      args.append('-inet6')
      args.append('{}/127'.format(ip))
    else:
      args.append('{}/32'.format(ip))
    args.append('{}'.format(gw_ip))
    pid, rc, out = run_cmd(args)

  return rc, out
# set_route

# -----------------------------------------------------------------------------
def delete_route(ip):
  ipv6 = ':' in ip
  os = platform.system()
  if os == 'Windows':
    # route delete <ip>
    args = ['route', 'delete']
    if ipv6:
      args.append('{}/127'.format(ip))
    else:
      args.append('{}/32'.format(ip))
    pid, rc, out = run_cmd(args)

    for line in out.splitlines():
      if re.search(r'failed:', line, re.IGNORECASE):
        rc = 1

  elif os == 'Linux':
    # route delete <ip>
    args = ['ip', 'route', 'del']
    args.append('{}'.format(ip))
    pid, rc, out = run_cmd(args)

  elif os == 'Darwin': # MacOS
    # route delete [-inet6] <ip>
    args = ['route', 'delete']
    if ipv6:
      args.append('-inet6')
      args.append('{}/127'.format(ip))
    else:
      args.append('{}/32'.format(ip))
    pid, rc, out = run_cmd(args)

  return rc, out
# delete_route

# =============================================================================
def create_self_signed_cert(cert_file, key_file):
  try:
    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.set_version(2) # = V3, zero based

    serial = int(hexlify(os.urandom(8)), 16)
    cert.set_serial_number(serial)

    subj = cert.get_subject()
    subj.C  = 'US'        # countryName
    subj.ST = 'Arizona'   # stateOrProvinceName
    subj.L  = 'Phoenix'   # localityName
    subj.O  = 'ACME Corp' # organizationName
  # subj.OU = 'CA'        # organizationalUnitName
    subj.CN = 'localhost' # commonName
    subj.emailAddress = 'acme-ca@acme.com' # emailAddress
    cert.set_issuer(subj)

    kusg = ['digitalSignature', 'keyEncipherment', 'dataEncipherment', 'keyAgreement']
  # kusg = ['digitalSignature', 'keyCertSign', 'cRLSign'] # CA
  # kusg = kusg + [ 'keyCertSign', 'cRLSign'] # add CA
    sans = ['DNS:localhost']
    ians = ['email:acme-ca@acme.com']

    cert.add_extensions([ # must be set in advance for authorityKeyIdentifier
      crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert)
    ])
    cert.add_extensions([
    # client extensions
      crypto.X509Extension(b'keyUsage', False, ', '.join(kusg).encode('utf-8')),
      crypto.X509Extension(b'subjectAltName', False, ', '.join(sans).encode('utf-8')),
    # crypto.X509Extension(b'extendedKeyUsage', False, b'clientAuth'), # not needed
    # CA extensions
    # crypto.X509Extension(b'basicConstraints', False, b'CA:TRUE'),
      crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always, issuer:always', issuer=cert),
      crypto.X509Extension(b'issuerAltName', False, ', '.join(ians).encode('utf-8'))
    ])

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60) # 10 years

    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    open(cert_file, 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(key_file, 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
  except:
    errmsg = sub_error(sys._getframe().f_code.co_name)
    log.critical(errmsg)
# create_self_signed_cert

# =============================================================================
class VPNProxySocket(websocket.WebSocketHandler):
  def __init__(self, *args, **kwargs):
    super(VPNProxySocket, self).__init__(*args, **kwargs)
    self.loop = ioloop.IOLoop.current()
    self.upstream_connect = Future()

  def check_origin(self, origin):
    log.info('Check origin: {!r}'.format(origin))
    return True # ignore origin

  def open(self):
    log.info('WS client connected')
    self.upstream_tcpclient = TCPClient()
    self.loop.spawn_callback(self.connect_upstream)

  @gen.coroutine
  def connect_upstream(self):
    try:
      log.info('Connecting to upstream {}'.format(upstream_url))
      if upstream_secure:
#       client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=rootca)
        client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        client_ctx.load_cert_chain(certificate, private_key)
        client_ctx.check_hostname = False # must be set before verify_mode
        client_ctx.verify_mode = ssl.CERT_NONE
        self.upstream = yield self.upstream_tcpclient.connect(upstream_host, upstream_port, ssl_options=client_ctx)
      else:
        self.upstream = yield self.upstream_tcpclient.connect(upstream_host, upstream_port)
    except:
      errmsg = sub_error(sys._getframe().f_code.co_name)
      log.critical(errmsg)
      try:
        self.close()
      except: pass
      return
    log.info('Connected to upstream')
    self.loop.spawn_callback(self.upstream_read_loop)
    self.upstream_connect.set_result(True)

  @gen.coroutine
  def upstream_read_loop(self):
    log.info('Start upstream loop')
    while True:
      try:
        message = yield self.upstream.read_bytes(msgbuf_len, partial=True)
      except Exception as e:
        if not isinstance(e, iostream.StreamClosedError):
          errmsg = sub_error(sys._getframe().f_code.co_name)
          log.critical(errmsg)
        log.warning('Upstream disconnected')
      # self.upstream.close()
        self.cleanup()
        break
      if debug:
        dtext = obj2asc(message).decode('utf-8')
        dtext = dtext[:dtext_len] + (dtext[dtext_len:] and '...')
        log.debug('Upstream >> {!r}'.format(dtext))
      try:
        yield self.write_message(message, binary=True)
      except Exception as e:
        if not isinstance(e, websocket.WebSocketClosedError):
          errmsg = sub_error(sys._getframe().f_code.co_name)
          log.critical(errmsg)
        log.warning('WS client disconnected')
      # self.close()
        self.cleanup()

  @gen.coroutine
  def on_message(self, message):
    try:
      if debug:
        dtext = obj2asc(message).decode('utf-8')
        dtext = dtext[:dtext_len] + (dtext[dtext_len:] and '...')
        log.debug('WS client >> {!r}'.format(dtext))
      if not self.upstream_connect.done():
        yield self.upstream_connect # wait for connect
      if isinstance(message, str):
        message = message.encode('Latin-1') # universal encode
      yield self.upstream.write(message)
    except Exception as e:
      if not isinstance(e, iostream.StreamClosedError):
        errmsg = sub_error(sys._getframe().f_code.co_name)
        log.critical(errmsg)
    # log.warning('Upstream disconnected')
    # self.upstream.close()
      self.cleanup()

  @gen.coroutine
  def on_close(self):
    log.info('WS client disconnected')

  def cleanup(self):
    # close both sides of connection
    try:
      self.upstream.close()
    except: pass
    try:
      self.close()
    except: pass
# VPNProxySocket

# =============================================================================
class VPNWSClient(object):
  def __init__(self, downstream):
    self.loop = ioloop.IOLoop.current()
    self.downstream = downstream
    self.upstream_connect = Future()

  @gen.coroutine
  def connect(self):
    try:
      log.info('Connecting to upstream {}'.format(upstream_url))
      if upstream_secure:
#       client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=rootca)
        client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        client_ctx.load_cert_chain(certificate, private_key)
        client_ctx.check_hostname = False # must be set before verify_mode
        client_ctx.verify_mode = ssl.CERT_NONE
        request = HTTPRequest(upstream_url, ssl_options=client_ctx)
        self.socket = yield websocket.websocket_connect(request)
      else:
        self.socket = yield websocket.websocket_connect(upstream_url)
    except:
      errmsg = sub_error(sys._getframe().f_code.co_name)
      log.critical(errmsg)
      try:
        self.socket.close()
      except: pass
      return
    log.info('Connected to upstream')
    self.loop.spawn_callback(self.upstream_read_loop)
    self.loop.spawn_callback(self.downstream_read_loop)
    self.upstream_connect.set_result(True)

  @gen.coroutine
  def upstream_read_loop(self):
    log.info('Reading from upstream in a loop')
    while True:
      try:
        message = yield self.socket.read_message()
        if message is None:
          break
      except Exception as e:
        if not isinstance(e, websocket.WebSocketClosedError):
          errmsg = sub_error(sys._getframe().f_code.co_name)
          log.critical(errmsg)
        log.warning('Upstream disconnected')
        break
      if debug:
        dtext = obj2asc(message).decode('utf-8')
        dtext = dtext[:dtext_len] + (dtext[dtext_len:] and '...')
        log.debug('Upstream >> {!r}'.format(dtext))
      try:
        if isinstance(message, str):
          message = message.encode('Latin-1') # universal encode
        self.downstream.write(message)
      except Exception as e:
        if not isinstance(e, iostream.StreamClosedError):
          errmsg = sub_error(sys._getframe().f_code.co_name)
          log.critical(errmsg)
        log.warning('Client disconnected')
        break
  # self.downstream.close()
    self.cleanup()

  @gen.coroutine
  def downstream_read_loop(self):
    log.info('Reading from client in a loop')
    while True:
      try:
        message = yield self.downstream.read_bytes(msgbuf_len, partial=True)
      except Exception as e:
        if not isinstance(e, iostream.StreamClosedError):
          errmsg = sub_error(sys._getframe().f_code.co_name)
          log.critical(errmsg)
        log.warning('Client disconnected')
        break
      if debug:
        dtext = obj2asc(message).decode('utf-8')
        dtext = dtext[:dtext_len] + (dtext[dtext_len:] and '...')
        log.debug('Client >> {!r}'.format(dtext))
      try:
        self.socket.write_message(message, binary=True)
      except Exception as e:
        if not isinstance(e, websocket.WebSocketClosedError):
          errmsg = sub_error(sys._getframe().f_code.co_name)
          log.critical(errmsg)
        log.warning('Upstream disconnected')
        break
  # self.socket.close()
    self.cleanup()

  def cleanup(self):
    # close both sides of connection
    try:
      self.downstream.close()
    except: pass
    try:
      self.socket.close()
    except: pass
# VPNWSClient

# =============================================================================
class ClientSideTCPSocket(TCPServer):
  upstream_handler = VPNWSClient

  def __init__(self, *args, **kwargs):
    super(ClientSideTCPSocket, self).__init__(*args, **kwargs)
    self.loop = ioloop.IOLoop.current()

  @gen.coroutine
  def handle_stream(self, stream, address):
    self.handler = self.upstream_handler(stream)
    self.loop.spawn_callback(self.handler.connect)
# ClientSideTCPSocket

# =============================================================================
def usage(prog, short=False):
  if not short:
    sys.stderr.write('{}\n'.format(prog_ver))
    sys.stderr.write('{}\n'.format(prog_cpy))
    sys.stderr.write('\n')
  sys.stderr.write('usage: %s [-?] [-d] [-f logfile] [-m {client|server}]\n' % prog)
  sys.stderr.write('             [-c filename] [-k filename]\n')
  sys.stderr.write('             [-l [{tcp|ssl}://]host[:port][/url]]\n')
  sys.stderr.write('              -u [{ws|wss}://]host[:port][/url]\n')
  if not short:
    sys.stderr.write('\n')
    sys.stderr.write('Establishes proxy WebSockets <--> TCP connections.\n')
    sys.stderr.write('\n')
    sys.stderr.write('optional arguments:\n')
    sys.stderr.write('  -?, --help            show this help message and exit\n')
    sys.stderr.write('  -d, --debug           show debug information (default: False)\n')
    sys.stderr.write('  -f, --logfile logfile log messages to logfile (default: stdout)\n')
    sys.stderr.write('  -m, --mode {client|server}\n')
    sys.stderr.write('                        run script in client or server mode (default: client)\n')
    sys.stderr.write('  -c, --cert filename   certificate for SSL connection (default: None)\n')
    sys.stderr.write('  -k, --key filename    private key for SSL connection (default: None)\n')
    sys.stderr.write('  -l, --local [{tcp|ssl}://]host[:port][/url]\n')
    sys.stderr.write('                        specifies local URL for listening (default: tcp://127.0.0.1:8000/)\n')
    sys.stderr.write('\n')
    sys.stderr.write('required arguments:\n')
    sys.stderr.write('  -u, --upstream [{ws|wss}://]host[:port][/url]\n')
    sys.stderr.write('                        specifies upstream URL (required) (default: tcp://127.0.0.1:80/)\n')
# usage

# =============================================================================
def main(argv):
  global debug, log
  global upstream_proto, upstream_host, upstream_port, upstream_path, upstream_url
  global local_secure, upstream_secure, certificate, private_key, route_ip

# argv = ['wsvpn.py', '-m', 'client']
  argv[0] = argv[0].replace('.PY', '.py')
  prog = ntbasename(argv[0])

  parser = argparse.ArgumentParser(description='Establishes proxy WebSockets <--> TCP connections',
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter, add_help=False)
#                   formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-?', '--help', action='store_true', default=False,
                       dest='help', help='show this help message and exit')
  parser.add_argument('-d', '--debug', action='store_true', default=False,
                       dest='debug', help='show debug information')
  parser.add_argument('-f', '--logfile', metavar='filename', default=None,
                       dest='logfile', help='log messages to logfile')
  parser.add_argument('-m', '--mode', choices=('client','server'), default='client',
                       dest='mode', help='run script in client or server mode')
  parser.add_argument('-r', '--setroute', action='store_true', default=False,
                       dest='setroute', help='set default route for VPN')
  parser.add_argument('-c', '--cert', metavar='filename', default=None,
                       dest='certificate', help='certificate for SSL connection')
  parser.add_argument('-k', '--key', metavar='filename', default=None,
                       dest='private_key', help='private key for SSL connection')
  parser.add_argument('-l', '--local', metavar='{{tcp|ssl}://}host[:port]{/url}', default='tcp://127.0.0.1:8000/',
                       dest='local', help='specifies local protocol and port for listening')
  required = parser.add_argument_group('required arguments')
  required.add_argument('-u', '--upstream', metavar='{{ws|wss}://}host[:port]{/url}', #required=True,
                        dest='upstream', help='specifies upstream URL (required)')
  try:
    args = parser.parse_args()
  except:
    usage(prog, short=True)
    return 1

  if args.help:
    usage(prog)
    return 0
  if args.upstream is None:
    usage(prog, short=True)
    sys.stderr.write('{}: error: argument -u/--upstream is required\n'.format(prog))
    return 1

  mode = args.mode
  setroute = args.setroute
  certificate = args.certificate
  private_key = args.private_key

  # set up logging
  debug = args.debug
  if debug: level = logging.DEBUG
  else: level = logging.INFO
  format = '[%(asctime)s %(levelname)s] %(message)s'
  try:
    if args.logfile is not None:
      logging.basicConfig(level=level, format=format,
        filename=args.logfile, filemode='ab') # wb
    else:
      logging.basicConfig(level=level, format=format)
  except:
    logging.basicConfig(level=level, format=format)
  # redirect stdout and stderr too
  log_stdout = logging.getLogger('STDOUT')
  sys.stdout = StreamToLogger(log_stdout, logging.INFO)
  log_stderr = logging.getLogger('STDERR')
  sys.stderr = StreamToLogger(log_stderr, logging.ERROR)
  log = logging.getLogger('WSVPN')

  # parse local URL
  local_url = args.local
  local_proto = None; local_path = None
  p = local_url.find('://')
  if p >= 0:
    local_proto = local_url[:p]
    local_url = local_url[p+3:]
  p = local_url.find('/')
  if p >= 0:
    local_path = local_url[p:]
    local_url = local_url[:p]
  local_host = None; local_port = None
  try:
    local_host, local_port = local_url.split(':', 1)
  except: pass
  if local_proto is None or len(local_proto) == 0:
    local_proto = 'tcp'
  if local_host is None:
    if local_url.isdigit():
      local_host = None
      local_port = local_url
    else: # not number
      local_host = local_url
      local_port = None
  if local_host is None or len(local_host) == 0:
    local_host = '127.0.0.1'
  if local_port is None or len(local_port) == 0:
    local_port = 8000
  if local_path is None or len(local_path) == 0:
    local_path = '/'

  local_secure = False
  if local_proto.startswith('ws'):
    # for WebSocket
    if local_proto.startswith('wss'):
      local_secure = True
    local_url = local_proto + '://' + local_host + ':' + str(local_port) + local_path
  else:
    # for TCP
    if local_proto.startswith('ssl') or local_proto.startswith('https'):
      local_secure = True
    #local_url = local_proto + ':' + str(local_port)
    local_url = local_proto + '://' + local_host + ':' + str(local_port)

  # parse upstream URL
  upstream_url = args.upstream
  upstream_proto = None; upstream_path = None
  p = upstream_url.find('://')
  if p >= 0:
    upstream_proto = upstream_url[:p]
    upstream_url = upstream_url[p+3:]
  p = upstream_url.find('/')
  if p >= 0:
    upstream_path = upstream_url[p:]
    upstream_url = upstream_url[:p]
  upstream_host = None; upstream_port = None
  try:
    upstream_host, upstream_port = upstream_url.split(':', 1)
  except: pass
  if upstream_proto is None or len(upstream_proto) == 0:
    upstream_proto = 'ws'
  if upstream_host is None:
    if upstream_url.isdigit():
      upstream_host = None
      upstream_port = upstream_url
    else: # not number
      upstream_host = upstream_url
      upstream_port = None
  if upstream_host is None or len(upstream_host) == 0:
    upstream_host = '127.0.0.1'
  if upstream_port is None or len(upstream_port) == 0:
    upstream_port = 80
  if upstream_path is None or len(upstream_path) == 0:
    upstream_path = '/'

  upstream_secure = False
  if upstream_proto.startswith('ws'):
    # for WebSocket
    if upstream_proto.startswith('wss'):
      upstream_secure = True
    upstream_url = upstream_proto + '://' + upstream_host + ':' + str(upstream_port) + upstream_path
  else:
    # for TCP
    if upstream_proto.startswith('ssl') or upstream_proto.startswith('https'):
      upstream_secure = True
    #upstream_url = upstream_proto + ':' + upstream_host + ':' + str(upstream_port)
    upstream_url = upstream_proto + '://' + upstream_host + ':' + str(upstream_port)

  try:
    log.info(prog_ver)
    log.info(prog_cpy)

    route_ip = None
    if setroute:
      addr_info = socket.getaddrinfo(upstream_host, upstream_port)
      upstream_ip = []
      for ai in addr_info:
        upstream_ip.append(ai[4][0])
      if len(upstream_ip):
        route_ip = upstream_ip[0]
        rc, out = set_route(route_ip)
        if rc != 0:
          log.error(out.strip())

    if local_secure or upstream_secure:
      if certificate is None:
        if private_key is None:
          certificate = ntdirname(__file__) + 'localhost.crt'
          private_key = ntdirname(__file__) + 'localhost.key'
          certificate = os.path.abspath(certificate)
          private_key = os.path.abspath(private_key)
          log.info('Creating new SSL certificate')
          create_self_signed_cert(certificate, private_key)
        else:
          log.error('{}: error: argument -c/--cert is required'.format(prog))
          return 1
      elif private_key is None:
        certificate = os.path.abspath(certificate)
        # guess private key name
        dir = ntdirname(certificate)
        name = ntbasename(certificate)
        ix = name.rfind('.')
        if ix > 0:
          name = name[:ix]
        name = name + '.key'
        private_key = dir + name
        private_key = os.path.abspath(private_key)
      else:
        certificate = os.path.abspath(certificate)
        private_key = os.path.abspath(private_key)
      log.info('Using certificate: {}'.format(certificate))
      if not os.path.isfile(certificate):
        log.error('{}: error: certificate file "{}" not found'.format(sys._getframe().f_code.co_name, certificate))
        return 1
      log.info('Using private key: {}'.format(private_key))
      if not os.path.isfile(private_key):
        log.error('{}: error: private key file "{}" not found'.format(sys._getframe().f_code.co_name, private_key))
        return 1

    # periodically check for signals and in case of signal try to terminate main loop
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    ioloop.PeriodicCallback(try_exit, 250).start()

    loop = ioloop.IOLoop.current()

    if mode == 'server':
      if debug:
        app = web.Application([
          (local_path, VPNProxySocket, {}) # route, handler, kwargs
        ], debug=True, autoreload=False)
      else:
        app = web.Application([
          (local_path, VPNProxySocket, {}) # route, handler, kwargs
        ])
      if local_secure:
#       server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=rootca)
        server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(certificate, private_key)
        server_ctx.check_hostname = False # must be set before verify_mode
        server_ctx.verify_mode = ssl.CERT_NONE
        server = HTTPServer(app, ssl_options=server_ctx)
      else:
        server = app

      log.info('Server listening on {}'.format(local_url))
      log.info('Will proxy requests to {}'.format(upstream_url))
      server.listen(local_port, address=local_host)

    elif mode == 'client':
      if local_secure:
#       server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=rootca)
        server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(certificate, private_key)
        server_ctx.check_hostname = False # must be set before verify_mode
        server_ctx.verify_mode = ssl.CERT_NONE
        server = ClientSideTCPSocket(ssl_options=server_ctx)
      else:
        server = ClientSideTCPSocket()

      log.info('Client listening on {}'.format(local_url))
      log.info('Will proxy requests to {}'.format(upstream_url))
      server.listen(local_port, address=local_host)

    loop.start()
    # never returns except when signal is received
  except:
    errmsg = sub_error(sys._getframe().f_code.co_name)
    log.critical(errmsg)
    return 1
  return 0
# main

# -----------------------------------------------------------------------------
if __name__ == '__main__':
  rc = main(sys.argv)
  sys.exit(rc)
