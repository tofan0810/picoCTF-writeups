### Bài toán
- Description
    - Can you get the flag?
Reverse engineer this binary.

### Giải
## 1. Giám định tệp tin (Reconnaissance)

Đầu tiên, chúng ta kiểm tra các lớp bảo vệ của tệp thực thi bằng công cụ `checksec`:

```bash
checksec --file=keygenme
```

**Kết quả:**

* **RELRO:** Full RELRO (Không thể ghi đè bảng GOT).
* **Stack:** Canary found (Có chống tràn stack).
* **NX:** NX enabled (Không thể thực thi mã trên stack).
* **PIE:** PIE enabled (Địa chỉ hàm thay đổi mỗi khi chạy).
* **Symbols:** **No Symbols** (Tệp đã bị stripped, không còn tên hàm gốc).

---

## 2. Phân tích tĩnh với Ghidra 

Vì tệp đã bị xóa Symbol, ta sử dụng **Ghidra** để dịch ngược mã máy thành mã C.

### Bước 1: Tìm hàm Main thực sự

Mở hàm `entry`, ta thấy hàm này gọi `__libc_start_main`. Tham số đầu tiên truyền vào chính là hàm Logic chính (Main):

```c
__libc_start_main(FUN_0010148b, param_2, ...);

```

=> Truy cập vào **`FUN_0010148b`**.

### Bước 2: Phân tích hàm Logic chính
```c
undefined8 FUN_0010148b(void)

{
  char cVar1;
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter your license key: ");
  fgets(local_38,0x25,stdin);
  cVar1 = FUN_00101209(local_38);
  if (cVar1 == '\0') {
    puts("That key is invalid.");
  }
  else {
    puts("That key is valid.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
Tại `FUN_0010148b`, chương trình thực hiện:

* `printf("Enter your license key: ");`
* `fgets(local_38, 0x25, stdin);`: Nhận đầu vào 37 ký tự.
* `cVar1 = FUN_00101209(local_38);`: Truyền key vào hàm kiểm tra.

---

## 3. Giải mã thuật toán kiểm tra (Deep Dive)

Truy cập vào hàm **`FUN_00101209`**, đây là nơi Flag được lắp ráp.
```c
undefined8 FUN_00101209(char *param_1)

{
  size_t sVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  int local_d0;
  int local_cc;
  int local_c8;
  int local_c4;
  int local_c0;
  uchar local_ba [2];
  byte local_b8 [16];
  byte local_a8 [16];
  uchar local_98 [32];
  char local_78 [13];
  undefined1 local_6b;
  undefined1 local_6a;
  undefined1 local_66;
  undefined1 local_60;
  undefined1 local_5e;
  undefined1 local_5b;
  char local_58 [32];
  uchar auStack_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  builtin_memcpy(local_98,"picoCTF{br1ng_y0ur_0wn_k3y_",0x1c);
  local_ba[0] = '}';
  local_ba[1] = '\0';
  sVar1 = strlen((char *)local_98);
  MD5(local_98,sVar1,local_b8);
  sVar1 = strlen((char *)local_ba);
  MD5(local_ba,sVar1,local_a8);
  local_d0 = 0;
  for (local_cc = 0; local_cc < 0x10; local_cc = local_cc + 1) {
    sprintf(local_78 + local_d0,"%02x",(ulong)local_b8[local_cc]);
    local_d0 = local_d0 + 2;
  }
  local_d0 = 0;
  for (local_c8 = 0; local_c8 < 0x10; local_c8 = local_c8 + 1) {
    sprintf(local_58 + local_d0,"%02x",(ulong)local_a8[local_c8]);
    local_d0 = local_d0 + 2;
  }
  for (local_c4 = 0; local_c4 < 0x1b; local_c4 = local_c4 + 1) {
    auStack_38[local_c4] = local_98[local_c4];
  }
  auStack_38[0x1b] = local_6b;
  auStack_38[0x1c] = local_66;
  auStack_38[0x1d] = local_5b;
  auStack_38[0x1e] = local_78[1];
  auStack_38[0x1f] = local_6a;
  auStack_38[0x20] = local_60;
  auStack_38[0x21] = local_5e;
  auStack_38[0x22] = local_5b;
  auStack_38[0x23] = local_ba[0];
  sVar1 = strlen(param_1);
  if (sVar1 == 0x24) {
    for (local_c0 = 0; local_c0 < 0x24; local_c0 = local_c0 + 1) {
      if (param_1[local_c0] != auStack_38[local_c0]) {
        uVar2 = 0;
        goto LAB_00101475;
      }
    }
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
LAB_00101475:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```
### Cấu trúc Flag (`auStack_38`):

1. **Phần đầu (Static):** `builtin_memcpy(local_98, "picoCTF{br1ng_y0ur_0wn_k3y_", 0x1c);` (28 ký tự đầu).
2. **Phần đuôi (Static):** `local_ba[0] = '}';`
3. **Phần động (Dynamic):** Chương trình tính **MD5** của phần đầu Flag và lưu vào chuỗi Hex `local_78`. Sau đó, nó "nhặt" các ký tự từ bộ nhớ stack để điền vào phần còn thiếu.

### Kỹ thuật truy vết Stack Offset:

Dựa vào khoảng cách địa chỉ giữa mảng MD5 (`local_78` tại `-0x78`) và các biến đơn lẻ, ta xác định được vị trí của chúng trong chuỗi MD5:

* **local_6b:** `0x78 - 0x6b = 13` => Index 13.
* **local_6a:** `0x78 - 0x6a = 14` => Index 14.
* **local_66:** `0x78 - 0x66 = 18` => Index 18.
* **local_60:** `0x78 - 0x60 = 24` => Index 24.
* **local_5e:** `0x78 - 0x5e = 26` => Index 26.
* **local_5b:** `0x78 - 0x5b = 29` => Index 29.

**Thứ tự lắp ráp vào Flag:**

| Vị trí Flag | Biến nguồn | Vị trí trong chuỗi MD5 |
| --- | --- | --- |
| Index 28 | `local_6b` | **13** |
| Index 29 | `local_66` | **18** |
| Index 30 | `local_5b` | **29** |
| Index 31 | `local_78[1]` | **1** |
| Index 32 | `local_6a` | **14** |
| Index 33 | `local_60` | **24** |
| Index 34 | `local_5e` | **26** |
| Index 35 | `local_5b` | **29** |

---

## 4. Script giải mã (Solution)

Sử dụng Python để tái tạo lại thuật toán MD5 và lấy đúng các ký tự theo Offset đã phân tích:

```python
import hashlib

# 1. Phần đầu cố định
prefix = "picoCTF{br1ng_y0ur_0wn_k3y_"

# 2. Tính MD5 của phần đầu
md5_hex = hashlib.md5(prefix.encode()).hexdigest()

# 3. Lắp ráp phần động theo đúng thứ tự logic của Ghidra
# Thứ tự index: 13, 18, 29, 1, 14, 24, 26, 29
dynamic = (md5_hex[13] + md5_hex[18] + md5_hex[29] + md5_hex[1] + 
           md5_hex[14] + md5_hex[24] + md5_hex[26] + md5_hex[29])

# 4. Kết quả cuối cùng
flag = prefix + dynamic + "}"
print(f"FLAG: {flag}")

```

**FLAG:** `picoCTF{br1ng_y0ur_0wn_k3y_xxxxxxxx}` *(Thay xxxxxxxx bằng kết quả chạy script)*.

### Note
- "Stripped" Binary và Entry Point - Trong các bài toán thực tế, lập trình viên thường dùng lệnh strip để xóa bỏ bảng ký hiệu (Symbol Table). Điều này làm mất tên các hàm và biến toàn cục, khiến việc dịch ngược khó khăn hơn:
    - Lý thuyết: Khi không có hàm main, ta phải tìm Entry Point (thường là địa chỉ bắt đầu của code). Tại đây, hàm khởi tạo của hệ thống (__libc_start_main) sẽ được gọi.
    - Kỹ thuật: Tham số đầu tiên của __libc_start_main luôn là địa chỉ của hàm main thực sự. Đây là "chìa khóa" để bắt đầu phân tích bất kỳ file ELF bị stripped nào.
- Tổ chức bộ nhớ Stack và Biến cục bộ (Stack Layout) - Tại sao Ghidra lại hiển thị các biến như local_6b, local_5e?
    - Lý thuyết: Trong ngôn ngữ C, các biến cục bộ được cấp phát trên Stack. Ghidra đặt tên dựa trên khoảng cách (offset) từ con trỏ khung hình (Frame Pointer - RBP) hoặc con trỏ ngăn xếp (Stack Pointer - RSP).
    - Phân tích bài toán: Khi ta thấy local_78 (mảng lưu MD5) nằm ở -0x78 và local_6b nằm ở -0x6b, khoảng cách giữa chúng là $0x78 - 0x6b = 13$ byte. Điều này chứng tỏ local_6b thực chất là một byte nằm bên trong vùng nhớ mà mảng MD5 đang chiếm giữ. Tác giả bài toán đã tận dụng việc "ép kiểu" (Type Casting) hoặc truy cập trực tiếp vào stack để đánh lừa các công cụ dịch ngược đơn giản.
- Cơ chế mã hóa MD5 trong Reverse Engineering - MD5 (Message-Digest Algorithm 5) tạo ra một chuỗi băm 128-bit (thường biểu diễn dưới dạng 32 ký tự Hex):
    - Nhận diện: Trong Ghidra, hãy tìm các hằng số khởi tạo đặc biệt của MD5 (như 0x67452301, 0xefcdab89) hoặc các hàm thư viện như MD5_Update.
    - Obfuscation (Làm rối): Thay vì so sánh Flag trực tiếp bằng chuỗi tĩnh, tác giả sử dụng MD5 của một phần Flag để tạo ra phần còn lại. Điều này ngăn cản việc tìm Flag bằng lệnh strings thông thường, buộc người chơi phải hiểu luồng dữ liệu (Data Flow) trong code.
- Các lớp bảo vệ Binary (Mitigations)
    - Canary: Một giá trị ngẫu nhiên đặt trước địa chỉ trả về của hàm. Nếu bạn nhập key quá dài làm tràn bộ nhớ, giá trị này bị thay đổi và chương trình sẽ gọi __stack_chk_fail để tự hủy thay vì thực thi mã độc.
    - PIE (Position Independent Executable): Khi PIE bật, mỗi lần chạy chương trình, địa chỉ nền (Base Address) sẽ thay đổi. Điều này khiến việc đặt breakpoint tại một địa chỉ cố định trong GDB trở nên khó khăn hơn, yêu cầu bạn phải tính toán địa chỉ dựa trên Offset.
- Vai trò của XREFs (Cross-References) - XREF là công cụ mạnh nhất trong Ghidra để định vị logic.
    - Ứng dụng: Khi tìm thấy chuỗi "Enter your license key:", ta xem XREF để biết hàm nào gọi chuỗi đó. Đây chính là cách nhanh nhất để tìm ra "hàm kiểm tra" (Validation Function) giữa hàng nghìn hàm vô danh trong một file stripped.

- **Bài học:** Ngay cả khi tệp đã bị **stripped**, việc dựa vào các chuỗi hằng số (Strings) và các hàm thư viện (như `sprintf`, `MD5`) vẫn giúp chúng ta định vị được logic cốt lõi.