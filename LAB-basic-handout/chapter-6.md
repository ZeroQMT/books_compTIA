# Ch6: Configuring the Snort IDS

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Ensure snort is installed/updated by typing **sudo apt-get install snort**. If prompted to continue, press y for yes and accept any other default settings.
3. View the snort main configuration file by typing **sudo nano /etc/snort/snort.conf.** This is where you can tweak snort, such as specifying a network IP address for variables such as HOME_NET.
4. Press CTRL+X to exit the nano text editor.
5. Type **cd /etc/snort/rules**, then ls. Snort include many preconfigured rule files that look for suspicious activity.
6. Create some custom snort rules by typing **sudo nano /etc/snort/rules/local.rules.**
7. You will create a snort rule that checks for ICMP network traffic, and another that checks for port 23 Telnet usage.
8. Enter (or copy and paste) the following rule taking careful note of colons versus semicolons:
   **alert icmp any -> $HOME_NET any (msg: "Testing ICMP"; sid: 1000001; rev:1; classtype: icmp-event;)**
   **alert tcp any -> any 23 (msg: "Telnet connection attempt"; sid: 1000002; rev:1;)**
9. Press CTRL+X, Y, then press ENTER.
10. Type **sudo snort -T -i eth0 -c /etc/snort/snort.conf -A console**. -A means print alerts to stdout, -q means quiet mode which doesn’t show banner or status report. We are using the -l (local lookback) interface here for testing purposes only.
11. To run snort, type **sudo snort -A console -l /var/log/snort -c /etc/snort/snort.conf**. -A means print alerts to stdout; console means print to terminal; -l is log directory; -c is config file.
12. Open another terminal emulator windows in Kali Linux (go to the menu in the upper left, then choose Favorites). Type **ping 127.0.0.1.**
13. Switch back to the terminal window where snort is running. You will see messages related to “Testing ICMP” as per our custom snort rule.
14. Press CTRL+C to exit snort, or close the terminal window.



# Ch6: Cấu hình Snort IDS

1. Bắt đầu và đăng nhập vào máy Kali Linux ảo của bạn với tư cách người dùng kali và mật khẩu kali.
2. Đảm bảo Snort được cài đặt/ cập nhật bằng cách gõ sudo apt-get install snort. Nếu được hỏi tiếp tục, nhấn y để đồng ý và chấp nhận mọi thiết đặt mặc định khác.
3. Xem tệp cấu hình chính của Snort bằng cách gõ sudo nano /etc/snort/snort.conf. Đây là nơi bạn có thể chỉnh sửa Snort, ví dụ như chỉ định một địa chỉ IP mạng cho các biến như HOME_NET.
4. Nhấn CTRL+X để thoát khỏi trình soạn thảo nano.
5. Gõ cd /etc/snort/rules, sau đó ls. Snort bao gồm nhiều tệp quy tắc preconfigured trông để phát hiện hoạt động đáng ngờ.
6. Tạo một số quy tắc Snort tùy chỉnh bằng cách gõ sudo nano /etc/snort/rules/local.rules.
7. Bạn sẽ tạo một quy tắc Snort kiểm tra lưu lượng ICMP mạng, và một quy tắc kiểm tra việc sử dụng Telnet trên cổng 23.
8. Nhập (hoặc sao chép và dán) các quy tắc sau, chú ý sự khác biệt giữa dấu hai chấm và dấu chấm phẩy:
   alert icmp any -> $HOME_NET any (msg: "Testing ICMP"; sid: 1000001; rev:1; classtype: icmp-event;)
   alert tcp any -> any 23 (msg: "Telnet connection attempt"; sid: 1000002; rev:1;)
9. Nhấn CTRL+X, Y, sau đó nhấn ENTER.
10. Gõ sudo snort -T -i eth0 -c /etc/snort/snort.conf -A console. -A có nghĩa là in cảnh báo ra stdout, -q có nghĩa là chế độ im lặng không hiển thị banner hoặc báo cáo trạng thái. Ở đây chúng ta đang dùng giao diện -l (local lookback) để thử nghiệm.
11. Để chạy snort, gõ sudo snort -A console -l /var/log/snort -c /etc/snort/snort.conf. -A có nghĩa là in cảnh báo ra stdout; console nghĩa là in ra màn hình; -l là thư mục ghi log; -c là tệp cấu hình.
12. Mở cửa sổ trình giả lập terminal khác trong Kali Linux (đi tới menu ở góc trên bên trái, chọn Favorites). Gõ ping 127.0.0.1.
13. Quay lại cửa sổ terminal có Snort đang chạy. Bạn sẽ thấy các thông điệp liên quan đến “Testing ICMP” như quy tắc tùy chỉnh đã định.
14. Nhấn CTRL+C để thoát Snort, hoặc đóng cửa sổ terminal.