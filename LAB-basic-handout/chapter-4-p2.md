# **Chapter 4: Scan a host using nmap**

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Open a terminal window and start the ssh service by typing **sudo service ssh start.**
3. Type **sudo netstat -an | grep :22** to filter netstat output to show only lines containing :22, the port number used by ssh.
4. Type **sudo netstat -an | grep :123** to see if the Network Time Protocol (NTP) is listening on port 123. Nothing is shown.
5. Start NTP by typing **sudo service ntp start.**
6. Verify NTP is running with the **sudo service ntp status** command, as well as the **netstat -an | grep :123** command.
7. Perform a UDP (S) and TCP (T) scan of the local Kali Linux host using the **sudo nmap 127.0.0.1 -sU -sT** command. Notice both NTP (UDP port 123) and SSH (TCP port 22) are listed in the scan output.
8. Perform an OS fingerprinting scan of the local Kali Linux host with the **sudo nmap -O 127.0.0.1** command. Notice the output shows that the host is running a Linux 2.6.x kernel.





# **Chương 4: Quét một máy chủ bằng nmap**

1. Bắt đầu và đăng nhập vào máy Kali Linux ảo của bạn với tư cách người dùng kali và mật khẩu kali.
2. Mở một cửa sổ terminal và khởi động dịch vụ ssh bằng cách gõ sudo service ssh start.
3. Gõ sudo netstat -an | grep :22 để lọc kết quả netstat và chỉ hiển thị các dòng chứa :22, là cổng ssh.
4. Gõ sudo netstat -an | grep :123 để xem liệu NTP (Network Time Protocol) có lắng nghe trên cổng 123 hay không. Không có gì hiển thị.
5. Khởi động NTP bằng cách gõ sudo service ntp start.
6. Xác nhận NTP đang chạy bằng lệnh sudo service ntp status, và đồng thời chạy lệnh netstat -an | grep :123.
7. Thực hiện quét UDP (S) và TCP (T) cho máy Kali Linux cục bộ bằng lệnh sudo nmap 127.0.0.1 -sU -sT. Lưu ý cả NTP (UDP cổng 123) và SSH (TCP cổng 22) đều được liệt kê trong kết quả quét.
8. Thực hiện một quét nhận diện hệ điều hành (OS fingerprinting) cho máy Kali Linux cục bộ với lệnh sudo nmap -O 127.0.0.1. Lưu ý kết quả cho thấy máy chủ đang chạy lõi Linux 2.6.x.