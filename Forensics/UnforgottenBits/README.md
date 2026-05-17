# Bài toán
- Description
    - Download this disk image and find the flag.
Note: if you are using the webshell, download and extract the disk image into /tmp not your home directory.
Download compressed disk image

# Giải
## GIAI ĐOẠN 1
- Đầu tiên thì cứ giải nén file ảnh đĩa gốc trước 
- Thử strings coi có file không :
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ strings disk.flag.img | grep -E "picoCTF\{.*\}"
```
- Và đương nhiên với bài hard thì không có
- Dùng mmls xem bảng phân vùng của nó:
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ mmls disk.flag.img
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
003:  000:001   0000206848   0000731135   0000524288   Linux Swap / Solaris x86 (0x82)
004:  000:002   0000731136   0002097151   0001366016   Linux (0x83)
```
- Liệt kê thử các file:
```
fls -r -o 731136 disk.flag.img
```
- Thì thấy nó quá nhiều file có vẻ là sẽ không hiệu quả rồi

## GIAI ĐOẠN 2
- Tiếp theo để xử lý file disk khó và to này = autopsy
- Khởi động autopsy:
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ sudo autopsy

============================================================================

                       Autopsy Forensic Browser 
                  http://www.sleuthkit.org/autopsy/
                             ver 2.24 

============================================================================
Evidence Locker: /var/lib/autopsy
Start Time: Sun May 17 05:35:23 2026
Remote Host: localhost
Local Port: 9999

Open an HTML browser on the remote host and paste this URL in it:

    http://localhost:9999/autopsy

Keep this process running and use <ctrl-c> to exit

```
- Copy http://localhost:9999/autopsy lên browser

- Click New Case. Điền tên Case (UnforgottenBits) và tên ở ô Investigator -> Bấm New Case.
- Click Add Host -> Giữ nguyên các thông số mặc định và bấm Add Host lần nữa.
- Click Add Image -> Chọn Add Image File. Ở ô Location, điền đường dẫn tuyệt đối của file ảnh đĩa disk.flag.img.
- Ta mở một terminal khác, gõ realpath disk.flag.img, copy chuỗi kết quả thu được dán vào ô Location.
- Chọn kiểu nhập là Symlink (hoặc Copy) -> Bấm Next -> Chọn phân vùng số 3 (Phân vùng Linux lớn nhất như mmls đã chỉ ra) -> Bấm Analyze.
- Rồi giờ vào trang analyze rồi thì phân tích thôi

## GIAI ĐOẠN 3
- Trong nền File analysis, analyze thư mục gallery trong home trước tôi vào: /3/home/yone/gallery -> xem coi có file ảnh nào đáng nghi k -> thấy 3 ảnh .bmp tải về 
- Tiếp tục trong /home:
    - Có vẻ như nó search gì đó trên google 1 kiểu decoding nào đó:
```
Contents Of File: /3/home/yone/.lynx/browsing-history.log


www.google.com
https://www.google.com/search?q=number+encodings&source=hp&ei=WeC9Y77KJ_iwqtsP0sGu6A0&iflsig=AK50M_UAAAAAY73uaRxDkbHRUH8jn4OVhOgM8riUqvVI&ved=0ahUKEwj-2r_EgL78AhV4mGoFHdKgC90Q4dUDCAk&uact=5&oq=number+encodings&gs_lcp=Cgdnd3Mtd2l6EAMyBggAEBYQHjIFCAAQhgMyBQgAEIYDMgUIABCGAzIFCAAQhgM6DgguEIAEELEDEIMBENQCOgsIABCABBCxAxCDAToRCC4QgAQQsQMQgwEQxwEQ0QM6CAgAELEDEIMBOgsILhCABBCxAxCDAToFCAAQgAQ6CAgAEIAEELEDOggILhCABBDUAjoHCAAQgAQQCjoHCC4QgAQQClAAWI0VYPAXaABwAHgDgAHDA4gB-iKSAQkwLjMuNS40LjOYAQCgAQE&sclient=gws-wiz
https://en.wikipedia.org/wiki/Church_encoding
https://cs.lmu.edu/~ray/notes/numenc/
https://www.wikiwand.com/en/Golden_ratio_base
```
- Tiếp tục đến với thư mục đáng nghi là /3/home/yone/notes/ ; thấy có 3 file txt, cứ tải về xem coi có hữu ích gì không
- bây giờ đã có 3 file txt và 3 file .bmp trước hết t cần tìm passphrase để analyze mấy file .bmp này -> tiếp tục mò vào /3/home/yone/Maildir thấy không có gì
- Chuyển sang thư mục cuối là /3/home/yone/irclogs:
    - Vào thằng /3/home/yone/irclogs/01/ trước thì thấy có file log cuộc nói chuyện của 2 thằng yone786/ (có thể là admin file disk này) và avidreader13/
    ```
    Contents Of File: /3/home/yone/irclogs/01/04/#avidreader13.log


    [08:12] <yone786> Ok, let me give you the keys for the light.
    [08:12] <avidreader13> I’m ready.
    [08:15] <yone786> First it’s steghide.
    [08:15] <yone786> Use password: akalibardzyratrundle
    [08:16] <avidreader13> Huh, is that a different language?
    [08:18] <yone786> Not really, don’t worry about it.
    [08:18] <yone786> The next is the encryption. Use openssl, AES, cbc.
    [08:19] <yone786> salt=0f3fa17eeacd53a9 key=58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508 iv=7a12fd4dc1898efcd997a1b9496e7591
    [08:19] <avidreader13> Damn! Ever heard of passphrases?
    [08:19] <yone786> Don’t trust em. I seed my crypto keys with uuids.
    [08:20] <avidreader13> Ok, I get it, you’re paranoid.
    [08:20] <avidreader13> But I have no idea if that would work.
    [08:21] <yone786> Haha, I’m not paranoid. I know you’re not a good hacker dude.
    [08:21] <avidreader13> Is there a better way?
    [08:22] * yone786 yawns.
    [08:24] <yone786> You’re ok at hacking. I’m good at writing code and using it
    [08:24] <avidreader13> What language are you writing in?
    [08:26] <yone786> C
    [08:26] <avidreader13> Oh, I see.
    [08:26] <yone786> I’m glad you like it. I’m sure you wouldn’t understand half of what I was doing.
    [08:28] <avidreader13> I understand enough, but I do wish you wouldn’t take so much time with it.
    [08:28] <yone786> Sorry. Well, I wish you could learn some things.
    [08:29] <avidreader13> But it’s an incredible amount of time you spend on it.
    [08:29] <yone786> Haha, don’t take it like that.

    ```
    - Oke ta thấy được thằng Yone nhắn cho bạn mật khẩu steghide đầu tiên là akalibardzyratrundle và các thông số openssl (AES, cbc, salt, key, iv)
- Tiếp theo sẽ đi analyze 3 file .bmp với mật khẩu đó:
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ steghide extract -sf vol4-3.home.yone.gallery.1.bmp -p akalibardzyratrundle
steghide extract -sf vol4-3.home.yone.gallery.2.bmp -p akalibardzyratrundle
steghide extract -sf vol4-3.home.yone.gallery.3.bmp -p akalibardzyratrundle
steghide extract -sf vol4-3.home.yone.gallery.7.bmp -p akalibardzyratrundle
wrote extracted data to "les-mis.txt.enc".
wrote extracted data to "dracula.txt.enc".
wrote extracted data to "frankenstein.txt.enc".
steghide: could not extract any data with that passphrase!
```
- Chỉ có thằng 7.bmp không được thôi cứ để đó
- Analyze 3 file .enc bị mã hóa đó = salt ở trên:
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ # 1. Giải mã file từ bức ảnh 1
openssl enc -aes-256-cbc -d -S 0f3fa17eeacd53a9 -K 58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508 -iv 7a12fd4dc1898efcd997a1b9496e7591 -in les-mis.txt.enc -out les-mis.txt

# 2. Giải mã file từ bức ảnh 2
openssl enc -aes-256-cbc -d -S 0f3fa17eeacd53a9 -K 58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508 -iv 7a12fd4dc1898efcd997a1b9496e7591 -in dracula.txt.enc -out dracula.txt

# 3. Giải mã file từ bức ảnh 3
openssl enc -aes-256-cbc -d -S 0f3fa17eeacd53a9 -K 58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508 -iv 7a12fd4dc1898efcd997a1b9496e7591 -in frankenstein.txt.enc -out frankenstein.txt
```
- Chạy 3 lệnh đó mở 3 file txt lên thì toàn thấy nội dung của sách thôi chả được gì
- Quay lại với 7.bmp chưa được và 3 file txt thấy nội dung 3 file txt:
```
chizazerite
guldulheen
I keep forgetting this, but it starts like: yasuoaatrox...
```
- Thử 1.txt và 2.txt đều không phải mk cho 7.bmp
- Thấy file 3.txt ... gì đó có thể nó là mật khẩu cho 7.bmp
- Không phải dân chơi game lắm nhưng mà cũng biết 2 con tướng trong liên minh là yasuo và aatrox -> giờ t sẽ thử tạo 1 wordlist gồm các tướng trong liên minh và ghép nó vào yasuoaatrox và thử với 7.bmp coi được k
- Tạo 1 file txt wordlist đó và chạy script python find_passphrase.py-> có output.txt
- Dùng stegcracker với file output.txt đó:
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ stegcracker vol4-3.home.yone.gallery.7.bmp output.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2026 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'vol4-3.home.yone.gallery.7.bmp' with wordlist 'output.txt'..
Successfully cracked file with password: yasuoaatroxashecassiopeia
Tried 1195 passwords
Your file has been written to: vol4-3.home.yone.gallery.7.bmp.out
yasuoaatroxashecassiopeia
```
- Đã crack được file 7.bmp và có được file 7.bmp.out -> là 1 file data bị mã hóa
- Chạy openssl với các bộ salt và key cũ ở trên thì không được => phải kiếm cái mới
- Ta vẫn chưa khai thác đề bài "UnforgottenBits" có thể nó là manh mối và ta còn 2 file txt chưa khai thác => Thế nên ta sẽ khai thác slack space của 2 file 1. và 2. txt còn lại
- Nhìn vào hình ta biết 2 file nằm ở inode 2365 và 2366
![image](https://github.com/user-attachments/assets/2380b630-4967-4cb2-a1a6-ae2765f4e2a8)

```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ # Tham số -s dùng để chỉ trích xuất duy nhất vùng Slack Space của file đó
icat -o 731136 -s disk.flag.img 2365                
chizazerite
01010010100.01001001000100.01001010000100.00101010010101.01000100100100.00100100000100.01000100000101.01000100001010.00000100000001.00001001010000.00000100010010.01000100010010.01001001001000.10001001000101.01001001010000.00001001000100.01001001010001.00000100000010.01000100010000.00001001001000.10000100010100.01000000010100.01001010000010.00101001010000.00001010101000.10000100100100.00101001000100.01000100010100.01001001010001.00000100010010.01000100010000.00001001000101.01000100010010.01000100010001.00000100001000.10001001000101.01001001001010.00000100010100.01000100000100.01000100010001.00000100000001.00000100001010.00000100010001.00001001000100.01000100000001.00000100001010.00000100001000.10000100000001.00000100010010.01001001001010.00000100000100.01000100010001.00000100001000.10001001010000.00001001010000.00000100000101.01001001000100.01000100010010.01000100010010.01001001000100.01000100010010.01000100000101.01001001000100.01001001001010.00000100010100.01000100010001.00000100000100.01000100000100.01000100000010.01000100010001.00001001000101.01000100010010.01000100000010.01001001010001.00001001001010.00001001001000.10000100000100.01001001000101.01001001000101.01000100010010.01001001010000.00000100010010.01001001001000.10001001000100.01000100010010.01000100010001.00000100000101.01000100010000.00001001001010.00001001000100.01000000010100.01001001010101.01001010100010.00100100100100.00100100010100.01000100000001.00000100010010.01000100001000.10000100001010.00000100010010.01001001010000.00000100001000.10000100010010.01001001010001.00001001001000.10000100010010.01001001001010.00001001000101.01000100000010.01001001001000.10000100001010.00001001000100.01000100001000.10000100010000.00001001010001.00000100000010.01000100010010.01001001010001.00000100000001.00001001010001.00001001010000.00001001000101.01000100000010.01000100000010.01000100010100.01001001010001.00000000010100.010     

┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ # Tham số -s dùng để chỉ trích xuất duy nhất vùng Slack Space của file đó
icat -o 731136 -s disk.flag.img 2366
guldulheen
```
- Ta chỉ thấy 1.txt có slack space => tiếp theo ta sẽ kiếm gì đó để dịch mã này
- Trong lúc tìm kiếm /3/home/yone/.lynx/browsing-history.log ; ta thấy chỉ có https://www.wikiwand.com/en/Golden_ratio_base là khả nghi và có thể đó là cách để dịch được slack space
![image](https://github.com/user-attachments/assets/9a7b1f0d-2af7-4e39-a472-af1e8c44001b)
- Từ script find_key_for_OUT.py ta có được:
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ python find_key_for_OUT.py
salt=2350e88cbeaf16c9
key=a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da
iv=908458e48fc8db1c5a46f18f0feb119f
```
- Cuối cùng thì chạy ra FLAG thôi!!!
```
┌──(kali㉿kali)-[/mnt/hgfs/picoCTF-writeups/Forensics/UnforgottenBits]
└─$ openssl enc -aes-256-cbc -d -S 2350e88cbeaf16c9 -K a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da -iv 908458e48fc8db1c5a46f18f0feb119f -in vol4-3.home.yone.gallery.7.bmp.out -out flag.txt
```
---

# Note

### 1. Định nghĩa Slack Space (Vùng không gian đệm trống)

* **Bản chất kỹ thuật:** Hệ điều hành quản lý và ghi dữ liệu lên ổ cứng theo từng khối có kích thước cố định gọi là **Cluster** (hoặc Block), thường là 4096 Bytes ($4\text{ KB}$). Khi một file được tạo ra, hệ điều hành luôn cấp phát một số lượng Cluster nguyên vẹn cho file đó. Nếu kích thước thực tế của file (`Logical Size`) nhỏ hơn kích thước được cấp phát trên đĩa (`Physical Size`), phần không gian thừa ra ở cuối Cluster sẽ bị bỏ hoang. Khoảng trống này chính là **Slack Space**.
* **Ứng dụng trong Kỹ thuật Giấu tin (Steganography):** Vì các lệnh đọc file thông thường (như `cat` hoặc mở bằng Text Editor) chỉ đọc dữ liệu dựa trên `Logical Size` rồi dừng lại, nên phần dữ liệu ghi lén vào Slack Space hoàn toàn bị ẩn đi. Để bóc tách vùng này, bắt buộc phải dùng các công cụ can thiệp sâu xuống tầng cấu trúc tệp tin (File System Level) như lệnh `icat -s` của bộ Sleuth Kit hoặc tính năng phân tích Slack của Autopsy.

### 2. Chiến thuật Hồ sơ hóa mục tiêu (Behavioral Profiling)

* Trận chiến CTF này không thể giải quyết bằng các công cụ quét tự động (như `strings` hay `grep`), mà đòi hỏi người chơi phải đóng vai một Thám tử số thực thụ để **xâu chuỗi hành vi của đối tượng (Yone)**:
1. Đọc lịch sử chat `irclogs` $\rightarrow$ Phát hiện thói quen sử dụng công cụ (`steghide`, `openssl`), triết lý bảo mật (paranoid) và tựa game yêu thích (*League of Legends*).
2. Đọc file cấu hình trình duyệt `browsing-history.log` $\rightarrow$ Thu hẹp thuật toán mã hóa dị toán học mà đối tượng đang nghiên cứu (*Golden ratio base*).
3. Phân tích file ghi chú `notes/3.txt` $\rightarrow$ Nhận diện định dạng khuyết của mật khẩu (`yasuoaatrox...`).


* **Bài học kinh nghiệm:** Khi đối mặt với các chuỗi mật khẩu bị ẩn hoặc thuật toán mã hóa không xác định, việc dựng lại chân dung hành vi và thói quen của mục tiêu sẽ giúp thu hẹp phạm vi tấn công (Targeted Wordlist), mang lại hiệu quả vượt trội so với việc Brute-force vét cạn mù quáng.

### 3. Quy luật cấu trúc khối dữ liệu cố định (Fixed-width Block Parsing)

* Một bẫy kỹ thuật rất lớn trong bài toán này là sự xuất hiện của các dấu chấm (`.`) trong chuỗi Slack Space. Nếu vội vàng sử dụng các hàm băm chuỗi mặc định như `.split('.')`, cấu trúc dữ liệu sẽ bị phá vỡ hoàn toàn và sinh ra chuỗi ký tự rác.
* **Bản chất cấu trúc:** Đối tượng (Yone) khi viết code mã hóa đã cố định mỗi ký tự chữ thành một khối nhị phân Phi (Phigit) có **độ dài chuẩn xác 15 ký tự** (bao gồm cả dấu chấm phân tách phần thập phân bên trong khối). Do đó, chìa khóa để giải mã thành công chuỗi cấu hình OpenSSL là phải cắt chuỗi theo độ dài cố định `[i: i + 15]` chứ không dựa vào ký tự phân cách.

### 4. Triệt tiêu sai số dấu phẩy động trong mã hóa toán học

* Hệ cơ số Tỉ lệ vàng ($\varphi \approx 1.618$) sử dụng các phép tính lũy thừa số mũ thực ($\varphi^n$ và $\varphi^{-n}$). Khi xử lý các phép toán này trên máy tính, sai số dấu phẩy động (`floating-point error`) của ngôn ngữ lập trình sẽ tự động tích tụ qua từng vòng lặp.
* **Giải pháp:** Việc sử dụng hàm làm tròn lên `math.ceil()` ngay sau khi tính toán mỗi block 15 ký tự là kỹ thuật bắt buộc để đưa giá trị số thực về đúng số nguyên đích của bảng mã ASCII, giúp khôi phục nguyên vẹn chuỗi thực thi `salt=... key=... iv=...` mà không bị sai lệch dù chỉ 1 bit.
