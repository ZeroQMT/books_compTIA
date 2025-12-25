# Chapter 11: Web Application Vulnerability Scanning using OWASP ZAP

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Open a terminal windows and type **sudo ifconfig lo up**. This will ensure that the local loopback interface is up and running. We are doing this since by default Wireshark will not capture local traffic as you will be for testing purposes.
3. From the Kali Linux menu in the upper left, type in **wire** and click wireshark.
4. In the Wireshark interfaces list, double-click **Loopback:lo**. This begins a packet capturing session on the local loopback interface.
5. In a Kali Linux terminal window, type **sudo hping3 -S 127.0.0.1 -a 1.2.3.4 -c 5**. This will send five (-c 5) packets to 127.0.0.1 but will show the source IP address (-a) as being 1.2.3.4.
6. Switch back to Wireshark. Notice there are five packets from 1.2.3.4. Click the red stop button to stop the packet capture. Keep Wireshark open.
7. Back in a terminal, type cd and press ENTER to switch to the current user home directory.
8. Create a fake payload file by **typing echo “This is nothing but fake data” > fake_payload.txt.**
9. Type **cat fake_payload.txt** to view the file contents.
10. Back in Wireshark, from the File menu choose File, Close, Continue without saving, then double-click the Loopback:lo interface listing to begin a new packet capture.
11. Switch back to a terminal window.
12. To send a completely forged packet, type **sudo hping3 127.0.0.1 -a 1.2.3.4 -p 555 -d 500 --file fake_payload.txt.** This sends 500 tiny packets with a destination port of 555 from 1.2.3.4 using our fake payload file as the packet data.
13. Switch back to Wireshark and stop the capture by clicking the red stop button. Click on any captured packet from 1.2.3.4. In the center panel next to **Transmission Control Protocol** (the TCP header), notice that the destination port is set to 555. Down in the bottom panel notice our fake payload showing up in the packet data.



# Chapter 11: Quét lỗ hổng Web Application bằng OWASP ZAP

1. Bắt đầu và đăng nhập vào máy Kali Linux ảo của bạn với tư cách người dùng kali và mật khẩu kali.
2. Mở một cửa sổ terminal và gõ sudo ifconfig lo up. Điều này đảm bảo giao diện vòng lặp (loopback) địa phương được bật và hoạt động. Chúng ta làm việc này vì Wireshark mặc định sẽ không ghi nhận lưu lượng local traffic khi bạn đang làm bài kiểm tra.
3. Từ menu Kali Linux ở góc trên bên trái, gõ wire và nhấp vào wireshark.
4. Trong danh sách các giao diện của Wireshark, nhấp hai lần vào Loopback:lo. Điều này bắt đầu một phiên ghi nhận gói tin trên giao diện vòng lặp địa phương.
5. Trong một cửa sổ terminal Kali Linux, gõ sudo hping3 -S 127.0.0.1 -a 1.2.3.4 -c 5. Lệnh này sẽ gửi năm gói tin tới 127.0.0.1 nhưng cho địa chỉ IP nguồn (-a) là 1.2.3.4.
6. Chuyển trở lại Wireshark. Lưu ý có năm gói tin từ 1.2.3.4. Nhấp nút dừng màu đỏ để dừng ghi nhận gói. Giữ Wireshark vẫn mở.
7. Quay lại cửa sổ terminal, gõ cd và nhấn ENTER để chuyển đến thư mục home của người dùng hiện tại.
8. Tạo một tệp payload giả bằng cách gõ echo "This is nothing but fake data" > fake_payload.txt.
9. Gõ cat fake_payload.txt để xem nội dung tệp.
10. Quay lại Wireshark, từ menu File chọn File, Close, Continue without saving, sau đó nhấp đúp vào danh sách Loopback:lo để bắt đầu một phiên ghi nhận gói mới.
11. Quay lại cửa sổ terminal.
12. Để gửi một gói tin hoàn toàn giả mạo, gõ sudo hping3 127.0.0.1 -a 1.2.3.4 -p 555 -d 500 --file fake_payload.txt. Lệnh này gửi 500 gói tin nhỏ với cổng đích 555 từ 1.2.3.4, dùng tệp payload giả làm dữ liệu gói.
13. Chuyển lại Wireshark và dừng ghi nhận bằng cách nhấp vào nút dừng màu đỏ. Nhấp vào bất kỳ gói tin nào từ 1.2.3.4. Trong bảng ở giữa bên cạnh Transmission Control Protocol (TCP header), lưu ý cổng đích được thiết lập là 555. Phía dưới ở bảng cuối cùng sẽ thấy payload giả của chúng ta hiển thị trong dữ liệu gói.