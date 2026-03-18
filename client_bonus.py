import socket
import struct

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5300
BUFFER = 4096
TIMEOUT = 5  # seconds


def send_to_resolver(sock, message):
    try:
        # encode message
        msg_bytes = message.encode()

        # prepend 2-byte length
        length = struct.pack("!H", len(msg_bytes))
        packet = length + msg_bytes

        # send request
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))

        # receive response
        data, _ = sock.recvfrom(BUFFER)

        # extract length and message
        resp_len = struct.unpack("!H", data[:2])[0]
        resp_msg = data[2:2 + resp_len].decode()

        print("\n--- Resolver Reply ---")
        print(resp_msg)
        print("----------------------\n")

    except socket.timeout:
        print("Error: Request timed out.")
    except Exception as e:
        print(f"Error: {e}")


def main():
    print("Simple DNS Client")
    print("Commands:")
    print("  AAAA <domain>")
    print("  /cache")
    print("  exit\n")

    # create socket once (reuse)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        while True:
            try:
                user_input = input(">>> ").strip()

                if user_input == "exit":
                    break
                elif user_input.startswith("AAAA "):
                    send_to_resolver(sock, user_input)
                elif user_input == "/cache":
                    send_to_resolver(sock, user_input)
                else:
                    print("Invalid command.")

            except KeyboardInterrupt:
                print("\nInterrupted. Use 'exit' to quit.")

    finally:
        sock.close()
        print("Socket closed.")


if __name__ == "__main__":
    main()