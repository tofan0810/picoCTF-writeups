# Bài toán
- Description
    - We found this packet capture. Recover the flag.

# Giải
- Mở file pcap thì thấy có số lượng lớn UDP packets
- Follow stream của nó thì thấy flag ở stream 6
# Note
### 1. Kỹ thuật ẩn giấu: Phân mảnh dữ liệu thô qua UDP (Raw UDP Data Fragmentation)
- **Bản chất:** Thay vì truyền tải một file hoàn chỉnh hoặc một chuỗi văn bản liên tục qua các giao thức ứng dụng phổ biến (như HTTP, FTP), kẻ tấn công sử dụng một kịch bản/script tự chế để xé nhỏ thông tin cần tuồn ra (ở đây là Flag).
- **Cách thức hoạt động:** Kẻ tấn công gửi dữ liệu theo cơ chế **từng ký tự một (Character-by-character)**. Cứ mỗi gói tin UDP thô chỉ chở đúng 1 hoặc 2 bytes dữ liệu (ví dụ: gói 1 chở chữ `p`, gói 2 chở chữ `i`, gói 3 chở chữ `c`...). Do UDP là giao thức không hướng kết nối (Connectionless), các gói tin này được bắn đi liên tục sang máy nhận mà không cần bắt tay thiết lập đường truyền.

### 2. Tại sao các bộ lọc tìm kiếm thông thường lại thất bại?
- **Lỗi khi dùng `udp contains "picoCTF"`:** Bộ lọc `contains` trong Wireshark chỉ hoạt động khi toàn bộ chuỗi ký tự mục tiêu nằm trọn vẹn trong phần Payload của **một gói tin đơn lẻ**. Vì Flag đã bị xé nhỏ ra hàng trăm gói tin khác nhau, không có một gói tin đơn lẻ nào chứa đủ chữ `picoCTF` $\rightarrow$ Kết quả lọc sẽ luôn trống không.
- **Dữ liệu rác ở các Stream đầu (Decoy Streams):** Tác giả bài toán thường rải traffic UDP vào nhiều luồng (Stream ID) khác nhau. Ở các Stream đầu (0, 1, 2...), dữ liệu gom được chỉ là ký tự rác (Junk text) nhằm đánh lạc hướng người phân tích, ép họ phải kiên trì duyệt qua các dòng chảy dữ liệu khác nhau để tìm ra luồng độc hại thực sự (Stream 5 hoặc Stream 6).

### 3. Kinh nghiệm phân tích & Dấu hiệu nhận biết (Forensics Mindset)
- **Dấu hiệu chí mạng (Kích thước gói tin):** Khi cuộn chuột (scroll) qua danh sách gói tin, nếu phát hiện một chuỗi hàng trăm gói tin UDP liên tục có **Kích thước Payload (Length) siêu nhỏ và bằng nhau chằn chặn** (chỉ 1 Byte hoặc vài Bytes), hãy nghi vấn ngay lập tức về hành vi tuồn dữ liệu phân mảnh.
- **Sức mạnh của `Follow Stream`:** Đối với các giao thức tầng giao vận (Layer 4) như TCP/UDP, tính năng `Follow Stream` là cứu cánh duy nhất để Wireshark tự động nhặt các mảnh Payload đơn lẻ từ các gói tin dựa trên cặp IP/Port nguồn-đích, sau đó sắp xếp và nối chúng lại theo đúng trình tự thời gian thành một văn bản hoàn chỉnh.
- **Cẩn trọng với lớp mã hóa phụ (ROT13/Ceasar):** Trong các bài CTF, chuỗi văn bản thu được sau khi Follow Stream đôi khi sẽ có dạng biến dị (ví dụ: `cvpbPGS{...}`). Đừng vội nghĩ mình tìm sai luồng, đó chỉ là lớp mã hóa dịch chuyển vòng ký tự (ROT13) được bọc thêm để bẫy người giải. Chỉ cần quăng chuỗi đó vào CyberChef để decode là ra Flag thật.