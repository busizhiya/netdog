# coding=utf-8
import socket as so
import sys
import getopt
import os
import threading
import time
import subprocess
import traceback
import random
import json
# 更改编码模式
try:
    if os.name != 'nt':
        os.system('export LC_ALL=en_US.UTF-8')
    else:
        pass
        # os.system('chcp 65001')
except Exception as e:
    print('[ERROR] can\'t change unicode to utf-8')
# 默认监听参数
target = '0.0.0.0'
port = 33445
listen = False  # 客户端/服务端
key = ''  # 密钥
sessions = dict()  # 会话储存
session_hold = 0  # 当前持有会话id
DEBUG = False  # 调试模式
FILES = dict()  # 接收文件
global_encoding = 'utf-8'  # 默认编码模式

# 命令行帮助
usage = '''usage:
        -h,--help   -->  帮助
        -t,--target -->  设置目标主机地址
        -p,--port   -->  设置目标主机端口
        -l,--listen -->  开启监听模式
        -d,--debug  -->  开启debug模式
        -k,--key    -->  设置登陆密码
'''
# 客户端帮助
client_usage = '''
客户端使用说明:
        help          -->  帮助
        disconnect,disc      -->  断开连接
                -i,--id	     -->  选择要断开的会话id(默认为当前持有会话)
        backgroud,bg  -->  后台模式
        session       -->  会话管理
                -l,--list    -->   列出所有会话
                -c,--change  -->   更改持有会话
        mode          -->  更改模式
                -t,--talk    -->    对话模式
                -s,--shell   -->    shell模式
        connect     -->  连接到远程主机
                -t,--target     -->   设置目标主机地址 (默认为--127.0.0.1)
                -p,--port       -->   设置目标主机端口 (默认为-33445)
                -P,--password   -->   使用密码登陆目标主机
        upload   `FILENAME` -->   上传文件
        download `FILENAME` -->   下载文件
'''
# 服务端帮助
server_usage = '''
服务端使用说明:
        help          -->  帮助
        disconnect,disc  -->  断开连接
        session       -->  会话管理
                -l,--list    -->   列出所有会话
                -c,--change  -->   更改持有会话
        mode          -->  更改模式
                -t,--talk    -->   对话模式
        key           -->  登陆密码管理
                -s,--set   -->    设置密码
                -l,--list  -->    显示密码
                -c,--close -->    关闭密码登陆(无需密码登录)
'''


def DEBUGP(msg=traceback.format_exc()):
    try:
        if DEBUG:
            print('[DEBUG] ', end='')
            print(msg)
    except:
        pass


def shelp(*args):
    print(server_usage)


def chelp(*args):
    print(client_usage)


# 加解密算法
def xor(data: bytes, key: str) -> bytes:
    if not key:
        return data
    dl = len(data)
    res = list()
    for x in range(dl):
        res.append(data[x] ^ ord(key[x % len(key)]))
    return bytes(res)


# 总发送接口
def SEND(c: so.socket, data: bytes, key=None):
    c.sendall(xor(data, key) + b'[EOF]')


# 总接收接口
def RECV(c: so.socket, key=None) -> bytes:
    buf = b''
    while True:
        data = c.recv(1024)
        if data[-5:] == b'[EOF]':
            buf += data[:-5]
            break
        else:
            buf += data
    DEBUGP(buf)
    return xor(buf, key)


# 客户端授权接口
def authnication_to(c: so.socket, password: str = None) -> (bool, str):
    try:
        c.settimeout(30)
        t_key = None
        while True:
            try:
                buf, binary = read_data(c, t_key)
            except so.timeout:
                return False, None
            oper = buf.split()
            if oper[0] == '[AU]':
                if oper[1] == 'CONNECT':
                    t_key = oper[2]
                    if password:
                        SEND(c, (b'[AU] TRY ' + encoder(password)), t_key)
                        continue
                    else:
                        print('[AU] Need Password!')
                        return False, None
                elif oper[1] == 'DP':
                    t_key = oper[2]
                    if password:
                        print('[AU] Remote_host don\'t need password')
                    return True, t_key
                elif oper[1] == 'SUCCESS':
                    print('[AU] Authnication success')
                    return True, password
                elif oper[1] == 'FAIL':
                    print("[AU] Authnication failed")
                    return False, None
    except Exception as e:
        DEBUGP()
        return False, None


# 会话定义类
class SESSION:
    session_nums = 0  # Global counter

    def __init__(self, TYPE: int, o1, o2=None, **kwargs):
        self.socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        self.password = kwargs.get('password', None)
        quiet = kwargs.get('quiet', True)
        global sessions, session_hold
        # try:
        if TYPE == 0:  # For Server
            self.type = 'Client'
            self.socket = o1
            threading.Thread(target=holder, args=(self,)).start()

        elif TYPE == 1:  # For Client
            self.type = 'Server'
            try:
                self.socket.connect((o1, o2))
                flag, password = authnication_to(self.socket, self.password)
                if not flag:
                    self.socket.close()
                    return
                self.password = password
                self.socket.settimeout(None)
                print('\n[INFO] success to connect to remote_host:' + o1 + ':' + str(o2))
                threading.Thread(target=holder, args=(self,)).start()
            except ConnectionRefusedError:
                if quiet:
                    print('\n[ERROR] remote_host:' + o1 + ':' + str(o2) + ' is not open')
                return
            except so.error as e:
                if quiet:
                    print('\n[ERROR] fail to connect to remote_host:' + o1 + ':' + str(o2))
                DEBUGP()
                return
            except Exception as e:
                DEBUGP()
                return

        # elif TYPE == 2:  # proxy
        #     self.R = kwargs['R']
        #     if self.R:
        #         print('[INFO] Do not Support reverse mode ')
        #         return
        #     else:
        #         self.type = 'Proxy'
        #         self.pn = 0
        #         self.ps = dict()
        #         self.s2 = o2
        #         try:
        #             self.socket.bind(o1)
        #             self.socket.listen(5)
        #         except:
        #             print('[ERROR] failed to bind proxy port')
        #             return
        #         threading.Thread(target=listen_porxy, args=(self.socket, o2, self)).start()
        #         return
        SESSION.session_nums += 1
        self.id = SESSION.session_nums
        sessions[self.id] = self
        session_hold = self.id

    def close(self, Resend: bool = True):
        global session_hold
        try:
            # if self.type == 'Proxy':
            #     for k in list(self.ps.keys()):
            #         self.ps[k].close()
            if Resend:
                try:
                    SEND(self.socket, b'[OPER] CLOSE', self.password)
                except:
                    pass
            sessions.pop(self.id)
            self.socket.close()
        except KeyError as e:
            # print('[ERROR] failed to pop id:' + str(self.id))
            pass
        except OSError as e:
            pass
        except BrokenPipeError:
            sessions.pop(self.id)
            self.socket.close()
        except Exception:
            DEBUGP()
            print('[ERROR] failed to close session:' + str(self.id))
        if session_hold == self.id:
            if len(sessions):
                session_hold, s = sessions.popitem()
                sessions[session_hold] = s
            else:
                session_hold = 0


# 服务端授权接口
def authoniztion(c: so.socket, addr, I_key: str = None) -> bool:
    try:
        t_key = "".join([random.choice("0123456789ABCDEF") for i in range(8)])
        flag = False
        if I_key:
            time.sleep(1)
            SEND(c, b'[AU] CONNECT ' + encoder(t_key))
            c.settimeout(3)
            try:
                buf, b = read_data(c, t_key)
            except so.timeout as e:
                SEND(c, b'[AU] NP', t_key)
                flag = False
            except so.error:
                flag = False
            oper = buf.split()
            if oper[0] == '[AU]':
                if oper[1] == 'TRY':
                    R_key = oper[2]
                    if R_key == I_key:
                        SEND(c, b'[AU] SUCCESS', t_key)
                        flag = True
                    else:
                        SEND(c, b'[AU] FAIL', t_key)
                        flag = False
        else:
            SEND(c, b'[AU] DP ' + encoder(t_key))
            flag = True
        if flag:
            c.settimeout(None)
            SESSION(0, c, password=I_key if I_key else t_key)
            print('\n[INFO] connect to remote_host:' + addr[0] + ' on local_port:' + str(addr[1]))
        else:
            c.close()
    except Exception as e:
        DEBUGP()
        return False


# 服务端监听接口
def listener(server: so.socket):
    """
    waiting for clients to connect
    """
    global session_hold
    while True:
        c, addr = server.accept()
        threading.Thread(target=authoniztion, args=(c, addr, key)).start()


# 传输解码接口
def decoder(data: bytes) -> str:
    """
    :param data: bytes-like str
    :return: auto decode as 1.Global 2.utf-8 3.gbk
    """
    try:
        data = data.decode(global_encoding)
    except UnicodeDecodeError:
        try:
            data = data.decode('utf-8')
        except UnicodeDecodeError:
            try:
                data = data.decode('gbk')
            except UnicodeDecodeError:
                print('[ERROR]can\'t decode')
                return None
    return data


# 传输编码接口
def encoder(data: str) -> bytes:
    res = b''
    if not data:
        return b''
    try:
        res = data.encode(global_encoding)
    except:
        try:
            res = data.encode('utf-8')
        except:
            try:
                res = data.encode('gbk')
            except:
                print('[ERROR]can\'t decode')
                return b'ENCODING ERROR'
    return res


# 封装的读取数据接口
def read_data(c: so.socket, key=None) -> (str, bytes):
    """
    :param key: key for xor crypto
    :param c: Read data from socket c
    :return data and decode as utf-8
    """
    data = RECV(c, key)
    buf = ''
    binary = b''
    if decoder(data[:5]) == '[F-B]':
        DEBUGP('recv binary file')
        binary += data[15:]
        buf = '[FILE] BODY ' + decoder(data[6:14])
    else:
        buf = decoder(data)
    return buf, binary


'''
！代理功能尚未完善！
# 代理管理接口
def proxy(opts, *args):
    st = dt = '127.0.0.1'
    dp = 33445
    sp = 33333
    R = False
    # if not opts:
    #     print('\n[ERROR] command `proxy` need options')
    #     return
    for O in opts:
        try:
            for opt in O:
                if opt in ('-p', '--sourceport'):
                    sp = int(O[1])
                elif opt in ('-P', '--desport'):
                    dp = int(O[1])
                elif opt in ('-r', '--reverse'):
                    R = True
                elif opt in ('-t', '--sourcetarget'):
                    st = O[1]
                elif opt in ('-T', '--destarget'):
                    dt = O[1]
        except ValueError as e:
            print('[ERROR] invalid port for proxy')

    SESSION(2, (st, sp), (dt, dp), R=R)


# 代理监听接口
def listen_porxy(s1: so.socket, s2: tuple, S: SESSION):
    """
    :param s1: listen socket
    :param s2: (addr,port)tuple for forward host
    :param S: Proxy SESSION
    wait for host connect to proxy port
    """
    global sessions, session_hold
    while True:
        try:
            c, addr = s1.accept()
        except ConnectionAbortedError:
            return
        threading.Thread(target=forwarder, args=(c, s2, S)).start()
        S.pn += 1
        S.ps[S.pn] = c


# 转发接口
def forwarder(s1: so.socket, s2: tuple, S: SESSION):
    """
    :param s1:  sender(client)
    :param s2:  receiver(server)
    :param S: Proxy SESSION
    """
    try:
        s1.setblocking(0)
        r2 = so.socket(so.AF_INET, so.SOCK_STREAM)
        r2.connect(s2)
        r2.setblocking(0)
        print(
            '[INFO] success to bind proxy ' + s1.getpeername()[0] + ':' + str(s1.getpeername()[1]) + ' to ' + s2[
                0] + ':' + str(
                s2[1]))
    except:
        print('[ERROR] failed to bind proxy')
        return
    while True:
        buf1 = b''
        try:
            while True:
                    data = s1.recv(1024)
                    buf1 += data
                    if len(data) < 1024:
                        break
        except BlockingIOError:
            pass
        if buf1:
            r2.sendall(buf1)
        buf2 = b''
        try:
            while True:
                data = s1.recv(1024)
                buf2 += data
                if len(data) < 1024:
                    break
        except BlockingIOError:
            pass
        if len(buf2):
            s1.sendall(buf2)
        if buf1 == 0 or buf2 == 0:
            try:
                s1.close()
                r2.close()
                print('[PROXY] SESSION ' + str(S.id) + ' closed')
            except:
                pass
            return
'''


# 操作处理接口

def holder(s: SESSION):
    """
    :param s: Holding session
    This function will keep listening.Waiting for signal from remote host
    It can also receive data from remote_host
    """
    c = s.socket
    buf = ''
    key = s.password
    while True:
        try:
            buf, binary = read_data(c, key)
            oper = buf.split()
            if not len(buf):
                # Remote host closed,but without CLOSE SIGN
                print('\n[INFO] remote_host:' + c.getpeername()[0] + ':' + str(c.getpeername()[1]) + ' closed')
                c.close()
                return
            if '[OPER]' == oper[0]:  # SOFTWARE OPERATION
                if 'CLOSE' == oper[1]:
                    # SESSION CLOSE
                    print('\n[INFO] remote_host:' + c.getpeername()[0] + ':' + str(c.getpeername()[1]) + ' closed')
                    # DON'T FORGET TO CLOSE!
                    s.close()
                    return
            elif '[MSG]' == oper[0]:
                print('\n[MSG-S-' + str(s.id) + '] ' + ''.join(buf[6:]))
            elif '[EXEC]' == oper[0]:
                try:
                    SEND(c, b'[RES] ' + subprocess.check_output(oper[1:], stderr=subprocess.STDOUT,shell=True if os.name=='nt' else False), key)
                except Exception as e:
                    if DEBUG:
                        print(repr(e))
                    SEND(c, b'[ERROR] [Server Error] EXEC Command', key)
            elif '[RES]' == oper[0]:
                print('\n' + ''.join(buf[6:]) + '\nshell>')
            elif '[ERROR]' == oper[0]:
                print('\n' + ''.join(buf[8:]))
            elif '[FILE]' == oper[0]:
                if oper[1] == 'HEAD':
                    if oper[2] == 'FILE':
                        ext = oper[3].split('.')[-1]
                        filename = ''.join(oper[3].split('.')[-2] + (
                            '_' + oper[4] if os.path.isfile(encoder(oper[3])) else '')) + '.' + ext  # G ONLY SIGN
                        FILES[oper[4]] = filename
                        print('\n[FILE] file size is ' + oper[5])
                        with open(filename, 'w'):  # create an empty file
                            pass
                    elif oper[2] == 'DIR':
                        pass
                elif oper[1] == 'BODY':
                    with open(FILES[oper[2]], 'ab') as f:
                        f.write(binary)
                elif oper[1] == 'END':
                    SEND(c,
                         encoder('[FILE] SUCCESS Success recieve file as ' + FILES[oper[2]]), key)
                    print('\n[INFO] Success saved file as `'+FILES[oper[2]]+'`')
                    FILES.pop(oper[2])
                elif oper[1] == 'SUCCESS':
                    print('\n[INFO-S-' + str(s.id) + ']' + buf[15:])
                elif oper[1] == 'FAIL':
                    print('\n[INFO-S-' + str(s.id) + ']' + buf[13:])
                elif oper[1] == 'ASK':
                    filename = oper[2]
                    if os.path.isfile(encoder(filename)):
                        sendfile(filename, s)
                    else:
                        SEND(c, b'[FILE] FAIL File ' + encoder(filename) + b' is not exists', key)


        except OSError as e:
            if e.args[0] == 9:  # Bad file descriptor
                s.close(False)
            return
        except BrokenPipeError:
            s.close(False)
            return
        except Exception:
        	print('[ERROR] unknown error')
        	DEBUGP()


# 密钥管理接口
def setkey(opts, *args, **kwargs):
    global key
    for O in opts:
        for opt in O:
            if opt in ('-l', '--list'):
                print(('[INFO] key is `' + key + '`') if key else '[INFO] Key is empty')
            elif opt in ('-s', '--set'):
                key = O[1]
                print('[INFO] Set key successful')
            elif opt in ('-c', '--close'):
                if key:
                    key = ''
                else:
                    print('[INFO] Key is empty')


# 服务端循环
def server_loop():
    # switch func
    server_func = {'disc': disconnect, 'disconnect': disconnect, 'bg': background, 'background': background,
                   'mode': mode, 'session': session, 'exit': exit_server, 'cls': clean_screen, 'clear': clean_screen,
                   'key': setkey, 'help': shelp}

    # create listen socket
    s = so.socket(so.AF_INET, so.SOCK_STREAM)
    try:  # try to bind
        s.bind((target, port))
    except:
        print('\n[ERROR] fail to bind listen_server on ' + str(port))
        os._exit(-1)
    print('\n[INFO] start listening')
    s.listen(5)
    threading.Thread(target=listener, args=(s,)).start()
    while True:
        oper = input('server >')
        if not oper or oper == '\n':
            continue
        opts, args = tuple(), tuple()
        # get command and options
        try:
            opts, args = getopt.gnu_getopt(oper.split(), 'lcc:ts:', ['list', 'change=', 'talk', 'set=', 'close'])
        except:
            print('invalid options')
            continue
        try:
            server_func.get(args[0])(opts, args)
        except Exception as e:
            DEBUGP()
            print('invalid command')


# 退出服务端
def exit_server(*args):
    """
    Exit server client
    """
    for k in list(sessions.keys()):
        print('\n[INFO] closing session:' + str(k))
        sessions[k].close()
    time.sleep(1)
    print('Bye')
    os._exit(0)


# 后台模式
def background(*args):
    global session_hold
    if session_hold:
        print('\n[INFO] success background session ' + str(session_hold))
        session_hold = 0
    else:
        print('\n[ERROR] no holding session now')


# 清理屏幕
def clean_screen(*args):
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


# 消息发送接口
def client_talk(c: so.socket, key=None):
    buf = ''
    while True:
        buf = input('talk >')
        if buf == '\\quit':
            return
        if buf == '\n' or not buf:
            continue
        try:
            SEND(c, encoder('[MSG] ' + buf), key)
        except:
            print('\n[ERROR] can\'t send message')
            return


# 命令发送接口
def client_shell(c: so.socket, key=None):
    buf = ''
    while True:
        buf = input('shell >')
        if buf == '\\quit':
            return
        if buf == '\n' or not buf:
            continue
        try:
            SEND(c, encoder('[EXEC] ' + buf), key)
        except:
            print('[ERROR] can\'t send command')
            return


# 模式选择接口
def mode(opts, *args):
    if not opts:
        print('\n[ERROR] command `mode` need option')
        return
    for opt in opts[0]:
        if opt in ('-t', '--talk'):
            if session_hold:
                s = sessions[session_hold]
                client_talk(s.socket, s.password)
            else:
                print('\n[ERROR] no connecting session now')
        if opt in ('-s', '--shell'):
            if session_hold:
                s = sessions[session_hold]
                client_shell(s.socket, s.password)
            else:
                print('\n[ERROR] no connecting session now')


# 会话管理接口
def session(opts, *args, **kwargs):
    if not opts:
        print('\n[ERROR] command `session` need options')
        return
    global session_hold
    for O in opts:
        for opt in O:
            if opt in ('-l', '--list'):
                if not len(sessions):
                    print('\n[INFO] session list is empty')
                    return
                print('\tHold ' + str(len(sessions)) + ' sessions\nid\tL_target\t\tR_target\tType')
                for id, s in sessions.items():
                    c = s.socket
                    try:
                        print(str(id) + '\t' +
                              c.getsockname()[0] + ':' +
                              str(c.getsockname()[1]) + '\t' +
                              c.getpeername()[0] + ':' +
                              str(c.getpeername()[1]) + '\t\t' +
                              s.type +
                              ('\t(holding)' if id == session_hold else '')
                              )
                    except Exception as e:
                        DEBUGP()
            elif opt in ('-c', '--change'):
                if not len(sessions):
                    print('\n[ERROR] no connecting session now')
                    return
                try:
                    if sessions[int(O[1])].type == 'Proxy':
                        print('[ERROR] can\'t change session to proxy_session')
                        return
                    session_hold = sessions[int(O[1])].id
                    print('\n[INFO] success change to session ' + O[1])
                except ValueError:
                    print('\n[ERROR] invalid change to session ' + O[1])


# 连接接口
def connect(opts, *args, **kwargs) -> SESSION:
    global session_hold
    global sessions
    c_target = kwargs.get('t', '127.0.0.1')
    c_port = kwargs.get('p', port)
    password = ''
    for O in opts:
        for opt in O:
            if opt in ('-t', '--target'):
                c_target = args[0][1]  # -_- what a special options parser...
            elif opt in ('-p', '--port'):
                try:
                    c_port = int(O[1])
                except ValueError:
                    print('\n[ERROR] invalid port')
            elif opt in ('-P', '--password'):
                password = O[1]
    return SESSION(1, c_target, c_port, password=password, kwargs=kwargs)


# 断开连接
def disconnect(*args):
    global session_hold
    # input disc id
    id = session_hold
    if not len(sessions):
        print('\n[ERROR] no connecting session now')
        return
    if args[0] and args[0][0][0] == '-c':
        try:
            id = int(args[0][0][1])
        except:
            print('[ERROR] invalid session_id')
            return
    try:
        sessions[id].close()
        print('\n[INFO] success to disconnect session ' + str(id))
    except Exception as e:
        print('\n[ERROR] failed to disconnect session ' + str(id))
        DEBUGP()


# 文件发送接口
def sendfile(filename: str, s: SESSION = None):
    if not s:
        s = sessions[session_hold]
    DEBUGP('send file')
    size = os.path.getsize(filename)
    print('[INFO] `'+filename+'` file size is ' + str(size))
    sign = "".join([random.choice("0123456789ABCDEF") for i in range(8)])
    SEND(s.socket, encoder('[FILE] HEAD FILE ' +
                           filename + ' ' +
                           sign + ' ' + # G ONLY SIGNS
                           str(size)),
         s.password)
    with open(filename, 'rb') as f:
        while True:
            buf = f.read(32767)
            if not buf:
                break
            SEND(s.socket, encoder('[F-B] ' +
                            sign +
                            ' ') + buf, s.password)
            DEBUGP('Send part data')
        DEBUGP("SEND SUCCESS")
    time.sleep(0.1)
    SEND(s.socket, encoder('[FILE] END ' + sign), s.password)


# 上传文件接口
def upload(opts, *args):
    if not session_hold:
        print('[ERROR] no holding session')
        return
    try:
        filename = args[0][1]
        if os.path.isfile(encoder(filename)):
            sendfile(filename)
        else:
            print('[ERROR] `' + filename + '` is not exists')
            return
    except IndexError:
        print('[ERROR] please input correct filename')


# 下载文件接口
def download(opts, *args):
    if not session_hold:
        print('[ERROR] no holding session')
        return
    try:
        filename = args[0][1]
        s = sessions[session_hold]
        SEND(s.socket, encoder('[FILE] ASK ' +
                               filename), s.password)

    except IndexError:
        print('[ERROR] please input correct filename')
        return


# 加载会话
def load():
    try:
        JSONS = dict()
        count = 0
        with open('SESSIONS.conf', 'r') as f:
            JSONS = json.load(f)
        print('[INFO] loading ' + str(len(JSONS)) + ' Re-session')
        for k in JSONS:
            # if k['type'] == 'Proxy':
            #     SESSION(2, k['s1'], k['s2'], R=k['R'])
            if k['type'] == 'Server':
                SESSION(1, k['r_host'][0], k['r_host'][1])
    except Exception as e:
        DEBUGP()
        print('[ERROR] Can\'t load sessions')


# 存储会话
def save():
    try:
        JSON = dict()
        JSONS = list()
        for k, v in sessions.items():
            JSON['type'] = v.type
            # if v.type == 'Proxy':
            #     JSON['R'] = v.R
            #     JSON['s1'] = v.socket.getsockname()
            #     JSON['s2'] = v.s2
            # else:
            JSON['r_host'] = v.socket.getpeername()
            JSONS.append(JSON)
        with open('SESSIONS.conf', 'w') as f:
            f.write(json.dumps(JSONS))
        print('[INFO] success save ' + str(len(JSONS)) + ' sessions')
    except Exception as e:
        if DEBUG:
            print(repr(e))
        print('[ERROR] failed to save sessions')


# 客户端循环
def client_loop():
    load()
    connect(tuple(),quiet=False)  # try to connect
    client_func = {'disc': disconnect, 'disconnect': disconnect, 'bg': background, 'background': background,
                   'mode': mode, 'session': session, 'connect': connect, 'exit': exit_client,
                   'cls': clean_screen, 'clear': clean_screen, 'upload': upload, 'download': download, 'help': chelp}
    while True:
        oper = input('client >')
        opts, args = [], []
        try:
            opts, args = getopt.gnu_getopt(oper.split(), 'lc:tst:p:i:P:',
                                           ['list', 'change=', 'talk', 'shell', 'target=', 'port=', 'id=', 'password='])
        except:
            print('invaild options')
            continue
        if not args and not opts:
            continue
        try:
            client_func.get(args[0])(opts, args)
        except Exception as e:
            if DEBUG:
                print(traceback.format_exc())
            else:
                print('invalid command')


# 退出客户端
def exit_client(*args):
    # Maybe save sessions
    save()
    for k in list(sessions.keys()):
        print('\n[INFO] closing session:' + str(k))
        sessions[k].close()
    time.sleep(1)
    print('Bye')
    os._exit(0)


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:p:ldk:", ['help', 'target=', 'port=', 'listen', 'debug', 'key='])
    except:
        print(usage)
    for opt, v in opts:
        if opt in ('-h', '--help'):
            print(usage)
        elif opt in ('-t', '--target'):
            target = v
        elif opt in ('-p', '--port'):
            port = int(v)
        elif opt in ('-l', '--listen'):
            listen = True
        elif opt in ('-d', '--debug'):
            DEBUG = True
        elif opt in ('-k', '--key'):
            key = v
        else:
            print(usage)
            os._exit(0)
    if DEBUG:
        print('[DEBUG] DEBUG MODE OPEN')
    if listen:
        try:
            server_loop()
        except KeyboardInterrupt:
            exit_server()
    else:
        try:
            client_loop()
        except KeyboardInterrupt:
            exit_client()
