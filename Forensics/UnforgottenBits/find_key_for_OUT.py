from math import ceil
from scipy.constants import golden

def phinary_to_decimal(phigit):
    # Tách chuỗi 15 ký tự thành 2 phần tại dấu chấm '.' (Ví dụ: "0101001" và "01001001...")
    integer, fraction = phigit.split(".")
    
    # Đảo ngược chuỗi phần nguyên (Ví dụ: "123" thành "321")
    # Mục đích: Duyệt từ phải sang trái để lũy thừa tăng dần từ 0, 1, 2... giống như hệ nhị phân
    integer = integer[::-1] 

    number = 0

    # Duyệt qua từng bit của phần nguyên
    for i, x in enumerate(integer):
        if x == "1":
            # Nếu bit là 1, cộng thêm giá trị: (Tỉ lệ vàng Phi) mũ (vị trí i)
            number = number + golden ** (i)
            
    # Duyệt qua từng bit của phần thập phân (sau dấu chấm)
    for i, x in enumerate(fraction):
        if x == "1":
            # Nếu bit là 1, cộng thêm giá trị: (Tỉ lệ vàng Phi) mũ âm (-(i+1))
            # Vị trí đầu tiên sau dấu chấm sẽ là mũ -1, tiếp theo là -2, -3...
            number = number + golden ** -(i+1)
    
    return number

if __name__ == "__main__":
    # Mở file slackSpace.txt chứa chuỗi nhị phân thô thu được từ lệnh icat
    with open("slackSpace.txt") as f:
        string = f.read()
        # Loại bỏ ký tự xuống dòng '\n' ở cuối file nếu có để tránh lệch nhịp đếm 15 ký tự
        string = string.rstrip("\n")
    
    # ĐÂY LÀ KHÚC CHÍ MẠNG: Yone quy định mỗi ký tự chữ sau khi mã hóa sẽ chiếm đúng 15 ký tự.
    # Lệnh này dùng List Comprehension để chặt khúc toàn bộ chuỗi dài: cứ 15 ký tự thành 1 phần tử trong mảng.
    phigits = [string[i: i + 15] for i in range(0, len(string), 15)]
    
    decoded_phi = []

    # Duyệt qua từng khối 15 ký tự (phigit) đã được cắt chuẩn
    for phigit in phigits:
        # Gọi hàm tính toán cơ số Phi -> Dùng hàm ceil() để làm tròn lên số nguyên gần nhất
        # Việc làm tròn lên (ceil) giúp triệt tiêu hoàn toàn sai số dấu phẩy động (float) của Python
        decoded_phi.append(ceil(phinary_to_decimal(phigit)))

    # map(chr, decoded_phi): Đổi toàn bộ các số nguyên vừa tính được sang ký tự ASCII tương ứng (ví dụ: 115 -> 's')
    # ''.join(...): Nối các ký tự lại với nhau thành chuỗi cấu hình hoàn chỉnh và in ra màn hình
    print(''.join(map(chr,decoded_phi)))