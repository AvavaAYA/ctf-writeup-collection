#!/usr/bin/env python3

import socket


def send_file(file_path, port):
    # 创建一个TCP套接字
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # 绑定到指定的地址和端口
        server_socket.bind(("0.0.0.0", port))
        # 开始监听连接
        server_socket.listen()

        print(f"Listening on port {port}...")

        # 等待客户端连接
        client_socket, client_address = server_socket.accept()

        with client_socket:
            print(f"Connection from {client_address}")

            # 读取并发送文件的内容
            with open(file_path, "rb") as file:
                while chunk := file.read():
                    client_socket.sendall(chunk)

            print("File sent.")


if __name__ == "__main__":
    # 指定要发送的文件和要监听的端口
    file_path = "uring_orw.bin"
    port = 4396

    send_file(file_path, port)
