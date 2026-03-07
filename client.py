import socket
import sys

# Khai báo hằng số
SERVER_IP = "192.168.161.133"
SERVER_PORT = 8888
BUF_SIZE = 1024

def main():
    # 1. Tạo socket UDP (AF_INET = IPv4, SOCK_DGRAM = UDP)
    try:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as e:
        print(f"Socket creation failed: {e}")
        sys.exit(1)

    # 2. Cài đặt Timeout 5 giây (thay thế cho setsockopt trong C)
    sockfd.settimeout(5.0)

    server_addr = (SERVER_IP, SERVER_PORT)
    print("--- DNS Resolver Client ---")

    while True:
        # Lấy đầu vào từ người dùng
        try:
            domain = input("\nEnter domain to resolve (or 'exit'): ").strip()
        except EOFError:
            break  # Thoát an toàn nếu gặp lỗi nhập (Ctrl+D)

        # Bỏ qua nếu người dùng chỉ nhấn Enter
        if not domain:
            continue

        if domain.lower() == "exit":
            break

        # Đóng khung thông điệp (thêm ký tự xuống dòng giống hệt snprintf trong C)
        message = f"{domain}\n"

        # 3. Bắn gói tin
        try:
            # Chuyển chuỗi (string) thành byte (encode) trước khi gửi
            sent_bytes = sockfd.sendto(message.encode('utf-8'), server_addr)
            print(f"[DEBUG] Đã bắn thành công {sent_bytes} bytes. Đang chờ phản hồi...")
        except socket.error as e:
            print(f"\n[LỖI] Không thể gửi gói tin đi: {e}")
            continue

        # 4. Chờ nhận phản hồi
        try:
            # recvfrom trả về dữ liệu (data) và địa chỉ người gửi (addr)
            data, _ = sockfd.recvfrom(BUF_SIZE)
            # Chuyển byte thành chuỗi (decode) và in ra
            print(f"\n{data.decode('utf-8')}")
        except socket.timeout:
            # Xử lý lỗi riêng cho trường hợp Timeout
            print("\n[LỖI] Timeout! Server không phản hồi sau 5 giây.")
        except socket.error as e:
            print(f"\n[LỖI] Lỗi khi nhận dữ liệu: {e}")

    # 5. Dọn dẹp tài nguyên
    sockfd.close()

if __name__ == "__main__":
    main()
