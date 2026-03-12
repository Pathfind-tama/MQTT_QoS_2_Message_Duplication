#!/usr/bin/env python3
"""
MQTT TLS 代理 - 两阶段阻断（带定时取消）
功能：
1. 第一阶段：阻断 Broker → Client 的第一个长度为35字节的 Application Data 包
2. 第二阶段：客户端重新连接后，阻断 Client → Broker 的第一个 Application Data 包（任意长度）
3. 320秒后自动取消所有阻断
4. 不解密 TLS 流量
5. 其他流量正常转发
"""

import socket
import threading
import time
from datetime import datetime
import struct

# 配置
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 18883
BROKER_HOST = '127.0.0.1'
BROKER_PORT = 8883

# 阻断配置
DROP_BROKER_TO_CLIENT_LENGTH = 35  # 第一阶段：阻断 Broker → Client 的 35 字节 Application Data
BLOCKING_DURATION = 320  # 阻断持续时间（秒）

# 全局状态
global_packet_number = 0
packet_number_lock = threading.Lock()
connection_count = 0  # 连接计数器
connection_count_lock = threading.Lock()
stage1_blocked = False  # 第一阶段是否已阻断
stage1_blocked_lock = threading.Lock()
start_time = None  # 程序启动时间
blocking_enabled = True  # 阻断是否启用
blocking_enabled_lock = threading.Lock()

# 日志文件
LOG_FILE = 'mqtt_tls_proxy_two_stage_block_timed.log'
log_lock = threading.Lock()

def print_and_log(msg):
    """打印并记录到日志文件"""
    print(msg)
    with log_lock:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(msg + '\n')

def format_timestamp():
    """格式化时间戳"""
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]

def get_elapsed_time():
    """获取程序运行时间（秒）"""
    if start_time:
        return time.time() - start_time
    return 0

def is_blocking_enabled():
    """检查阻断是否启用"""
    with blocking_enabled_lock:
        return blocking_enabled

def disable_blocking():
    """禁用阻断"""
    global blocking_enabled
    with blocking_enabled_lock:
        blocking_enabled = False

def get_next_packet_number():
    """获取下一个包编号"""
    global global_packet_number
    with packet_number_lock:
        global_packet_number += 1
        return global_packet_number

def increment_connection_count():
    """增加连接计数"""
    global connection_count
    with connection_count_lock:
        connection_count += 1
        return connection_count

def is_stage1_blocked():
    """检查第一阶段是否已阻断"""
    with stage1_blocked_lock:
        return stage1_blocked

def set_stage1_blocked():
    """设置第一阶段已阻断"""
    global stage1_blocked
    with stage1_blocked_lock:
        stage1_blocked = True

def parse_tls_record(data):
    """解析 TLS 记录"""
    if len(data) < 5:
        return None

    content_type = data[0]
    version = struct.unpack('!H', data[1:3])[0]
    length = struct.unpack('!H', data[3:5])[0]

    content_types = {
        0x14: 'ChangeCipherSpec',
        0x15: 'Alert',
        0x16: 'Handshake',
        0x17: 'Application Data',
        0x18: 'Heartbeat'
    }

    version_names = {
        0x0301: 'TLS 1.0',
        0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3',
    }

    result = {
        'content_type': content_type,
        'content_type_name': content_types.get(content_type, 'Unknown'),
        'version': version,
        'version_str': version_names.get(version, f'Unknown (0x{version:04x})'),
        'length': length,
        'total_length': 5 + length,
        'record_layer_length': 5 + length
    }

    # 如果是握手消息，解析握手类型
    if content_type == 0x16 and len(data) >= 6:
        handshake_type = data[5]
        handshake_types = {
            0x00: 'HelloRequest',
            0x01: 'ClientHello',
            0x02: 'ServerHello',
            0x0b: 'Certificate',
            0x0c: 'ServerKeyExchange',
            0x0d: 'CertificateRequest',
            0x0e: 'ServerHelloDone',
            0x0f: 'CertificateVerify',
            0x10: 'ClientKeyExchange',
            0x14: 'Finished',
        }
        result['handshake_type'] = handshake_type
        result['handshake_type_name'] = handshake_types.get(handshake_type, f'Unknown ({handshake_type})')

        if len(data) >= 9:
            handshake_length = struct.unpack('!I', b'\x00' + data[6:9])[0]
            result['handshake_length'] = handshake_length

    return result


class ConnectionState:
    """连接状态类"""
    def __init__(self, connection_id, conn_number):
        self.connection_id = connection_id
        self.conn_number = conn_number
        self.client_to_broker_app_data_count = 0  # Client → Broker 的 Application Data 计数
        self.broker_to_client_app_data_count = 0  # Broker → Client 的 Application Data 计数
        self.lock = threading.Lock()

    def increment_client_to_broker_app_data(self):
        """增加 Client → Broker 的 Application Data 计数"""
        with self.lock:
            self.client_to_broker_app_data_count += 1
            return self.client_to_broker_app_data_count

    def increment_broker_to_client_app_data(self):
        """增加 Broker → Client 的 Application Data 计数"""
        with self.lock:
            self.broker_to_client_app_data_count += 1
            return self.broker_to_client_app_data_count


def forward_data(source, destination, direction, connection_id, conn_state):
    """转发数据，根据阶段阻断不同的包"""
    try:
        buffer = b''
        while True:
            data = source.recv(4096)
            if not data:
                msg = f"[{format_timestamp()}] [{connection_id}] {direction}- Connection closed"
                print_and_log(msg)
                break

            buffer += data
            temp_buffer = buffer
            data_to_forward = b''

            while len(temp_buffer) >= 5:
                tls_info = parse_tls_record(temp_buffer)
                if not tls_info or len(temp_buffer) < tls_info['total_length']:
                    break

                pkt_no = get_next_packet_number()
                timestamp = format_timestamp()
                elapsed = get_elapsed_time()
                src_dst = "Client → Broker" if direction == 'client->broker' else "Broker → Client"
                protocol = "TLSv1.2"
                length = tls_info['record_layer_length']

                # 构建 Info 字段
                if 'handshake_type_name' in tls_info:
                    info = f"{tls_info['handshake_type_name']}"
                else:
                    info = f"{tls_info['content_type_name']}"

                packet_data = temp_buffer[:tls_info['total_length']]
                should_block = False
                block_reason = ""

                # 检查是否超过阻断时间
                if elapsed >= BLOCKING_DURATION and is_blocking_enabled():
                    disable_blocking()
                    msg = f"\n{'='*80}"
                    print_and_log(msg)
                    msg = f"⏰ TIME LIMIT REACHED: {BLOCKING_DURATION}s elapsed - ALL BLOCKING DISABLED"
                    print_and_log(msg)
                    msg = f"{'='*80}\n"
                    print_and_log(msg)

                # 判断是否需要阻断（只有在阻断启用时才执行）
                if is_blocking_enabled() and tls_info['content_type_name'] == 'Application Data':
                    # 第一阶段：全局阻断第一个 Broker → Client 的 35 字节 Application Data（无条件）
                    if (direction == 'broker->client' and
                        not is_stage1_blocked() and
                        length == DROP_BROKER_TO_CLIENT_LENGTH):

                        # 无条件阻断第一个35字节的包
                        should_block = True
                        block_reason = f"STAGE 1 - Broker→Client 35-byte App Data (Time: {elapsed:.1f}s)"
                        set_stage1_blocked()
                        msg = f"\n{'='*80}"
                        print_and_log(msg)
                        msg = f"🎯 STAGE 1 TRIGGERED: Blocking Broker → Client 35-byte Application Data"
                        print_and_log(msg)
                        msg = f"{'='*80}\n"
                        print_and_log(msg)

                    # 第二阶段：只有在第一阶段完成后，才阻断 Client → Broker 的第一个 Application Data
                    elif (direction == 'client->broker' and
                          is_stage1_blocked() and
                          conn_state.conn_number >= 2):  # 第二次及以后的连接

                        app_data_count = conn_state.increment_client_to_broker_app_data()
                        if app_data_count == 1:  # 第一个 Application Data
                            should_block = True
                            block_reason = f"STAGE 2 - Client→Broker First App Data (Length={length}, Time: {elapsed:.1f}s)"
                            msg = f"\n{'='*80}"
                            print_and_log(msg)
                            msg = f"🎯 STAGE 2 TRIGGERED: Blocking Client → Broker First Application Data (Length={length})"
                            print_and_log(msg)
                            msg = f"{'='*80}\n"
                            print_and_log(msg)
                    else:
                        # 只是计数，不阻断
                        if direction == 'client->broker':
                            conn_state.increment_client_to_broker_app_data()
                        else:
                            conn_state.increment_broker_to_client_app_data()

                # 执行阻断或转发
                if should_block:
                    info += f" [🚫 BLOCKED - {block_reason}]"
                    msg = f"{pkt_no:6d}  {timestamp}{src_dst:20s}{protocol:8s}{length:6d}{info}"
                    print_and_log(msg)
                    msg = f"         ⛔ Packet BLOCKED - {block_reason}"
                    print_and_log(msg)
                    print_and_log("")
                else:
                    # 正常转发
                    data_to_forward += packet_data
                    msg = f"{pkt_no:6d}  {timestamp}{src_dst:20s}{protocol:8s}{length:6d}{info}"
                    print_and_log(msg)

                # 移动到下一个 TLS 记录
                temp_buffer = temp_buffer[tls_info['total_length']:]
                buffer = temp_buffer

            # 转发数据（如果有）
            if data_to_forward:
                destination.sendall(data_to_forward)

    except Exception as e:
        msg = f"[{format_timestamp()}] [{connection_id}] Error in {direction}: {e}"
        print_and_log(msg)
    finally:
        try:
            source.close()
            destination.close()
        except:
            pass


def handle_client(client_socket, client_addr, connection_id):
    """处理客户端连接"""
    conn_number = increment_connection_count()
    connection_id_full = f"{client_addr[0]}:{client_addr[1]}"

    # 创建连接状态
    conn_state = ConnectionState(connection_id_full, conn_number)

    elapsed = get_elapsed_time()
    separator = "="*80
    msg = f"\n{separator}"
    print_and_log(msg)
    msg = f"[{format_timestamp()}] 🔗 Connection #{conn_number} from {client_addr} (Elapsed: {elapsed:.1f}s)"
    print_and_log(msg)

    # 显示当前阶段
    if not is_blocking_enabled():
        msg = f"[{format_timestamp()}] 📍 Current Stage: BLOCKING DISABLED (Time limit reached)"
    elif not is_stage1_blocked():
        msg = f"[{format_timestamp()}] 📍 Current Stage: STAGE 1 (Waiting to block Broker→Client 35-byte)"
    else:
        if conn_number >= 2:
            msg = f"[{format_timestamp()}] 📍 Current Stage: STAGE 2 (Will block Client→Broker first App Data)"
        else:
            msg = f"[{format_timestamp()}] 📍 Current Stage: Between STAGE 1 and STAGE 2"
    print_and_log(msg)
    msg = f"{separator}"
    print_and_log(msg)

    try:
        # 连接到 broker
        broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        broker_socket.connect((BROKER_HOST, BROKER_PORT))
        msg = f"[{format_timestamp()}] [{connection_id_full}] Connected to broker {BROKER_HOST}:{BROKER_PORT}"
        print_and_log(msg)

        # 打印表头
        msg = f"\n{'No.':>6}  {'Time':>12}  {'Source → Destination':<20}{'Protocol':<8}{'Length':>6}{'Info'}"
        print_and_log(msg)
        msg = "-"*80
        print_and_log(msg)

        # 创建转发线程
        client_to_broker = threading.Thread(
            target=forward_data,
            args=(client_socket, broker_socket, 'client->broker', connection_id_full, conn_state)
        )
        broker_to_client = threading.Thread(
            target=forward_data,
            args=(broker_socket, client_socket, 'broker->client', connection_id_full, conn_state)
        )

        client_to_broker.daemon = True
        broker_to_client.daemon = True

        client_to_broker.start()
        broker_to_client.start()

        client_to_broker.join()
        broker_to_client.join()

    except Exception as e:
        msg = f"[{format_timestamp()}] [{connection_id_full}] Error: {e}"
        print_and_log(msg)
    finally:
        client_socket.close()
        msg = f"\n{separator}"
        print_and_log(msg)
        msg = f"[{format_timestamp()}] [{connection_id_full}] Connection #{conn_number} closed"
        print_and_log(msg)
        msg = f"{separator}\n"
        print_and_log(msg)


def main():
    """主函数"""
    global start_time
    start_time = time.time()

    # 清空日志文件
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"MQTT TLS Proxy Two-Stage Block (Timed) Log - Started at {datetime.now()}\n")
        f.write("=" * 80 + "\n\n")

    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print("║     MQTT TLS Proxy - Two-Stage Blocking Strategy (Timed)                 ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝")
    print()
    print(f"Proxy listening on: {PROXY_HOST}:{PROXY_PORT}")
    print(f"Forwarding to:      {BROKER_HOST}:{BROKER_PORT} (TLS)")
    print(f"Log file:           {LOG_FILE}")
    print()
    print("Two-Stage Blocking Strategy:")
    print(f"  📍 STAGE 1: Block Broker → Client, Application Data, Length = {DROP_BROKER_TO_CLIENT_LENGTH}bytes")
    print(f"              (First connection, first 35-byte App Data from Broker)")
    print(f"  📍 STAGE 2: Block Client → Broker, First Application Data (ANY length)")
    print(f"              (After reconnection, first App Data from Client)")
    print()
    print(f"⏰ Time Limit: {BLOCKING_DURATION}seconds")
    print(f"   After {BLOCKING_DURATION}s, all blocking will be automatically disabled")
    print()
    print("Purpose: Test MQTTX client reaction to two-stage blocking with time limit")
    print()
    print("Press Ctrl+C to stop")
    print("-" * 80)

    # 创建监听 socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((PROXY_HOST, PROXY_PORT))
    server_socket.listen(5)

    connection_counter = 0

    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            connection_counter += 1
            connection_id = f"CONN-{connection_counter}"

            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr, connection_id)
            )
            client_thread.daemon = True
            client_thread.start()

    except KeyboardInterrupt:
        print("\n\nProxy stopped by user")
    finally:
        server_socket.close()

if __name__ == '__main__':
    main()

