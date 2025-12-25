# Chapter 12: Use hping3 to Forge Network Packets

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Open a terminal windows and type **sudo ifconfig lo up**. This will ensure that the local loopback interface is up and running. We are doing this since by default Wireshark will not capture local traffic as you will be for testing purposes.
3. From the Kali Linux menu in the upper left, type in wire and click wireshark.
4. In the Wireshark interfaces list, double-click **Loopback:lo.** This begins a packet capturing session on the local loopback interface.
5. In a Kali Linux terminal window, type **sudo hping3 -S 127.0.0.1 -a 1.2.3.4 -c 5.** This will send five (-c 5) packets to 127.0.0.1 but will show the source IP address (-a) as being 1.2.3.4.
6. Switch back to Wireshark. Notice there are five packets from 1.2.3.4. Click the red stop button to stop the packet capture. Keep Wireshark open.
7. Back in a terminal, type cd and press ENTER to switch to the current user home directory.
8. Create a fake payload file by **typing echo “This is nothing but fake data” > fake_payload.txt.**
9. Type **cat fake_payload.txt** to view the file contents.
10. Back in Wireshark, from the File menu choose File, Close, Continue without saving, then double-click the Loopback:lo interface listing to begin a new packet capture.
11. Switch back to a terminal window.
12. To send a completely forged packet, type **sudo hping3 127.0.0.1 -a 1.2.3.4 -p 555 -d 500 --file fake_payload.txt.** This sends 500 byte packets with a destination port of 555 from 1.2.3.4 using our fake payload file as the packet data.
13. Switch back to Wireshark and stop the capture by clicking the red stop button. Click on any captured packet from 1.2.3.4. In the center panel next to **Transmission Control Protocol** (the TCP header), notice that the destination port is set to 555. Down in the bottom panel notice our fake payload showing up in the packet data.





# Chapter 12: Sử dụng hping3 để giả mạo gói mạng

1. Khởi động và đăng nhập vào máy ảo Kali Linux của bạn với tư cách người dùng kali và mật khẩu kali.
2. Mở một cửa sổ terminal và gõ sudo ifconfig lo up. Điều này đảm bảo rằng giao diện vòng lặp địa phương (loopback) được bật và hoạt động. Chúng ta làm việc này vì Wireshark mặc định sẽ không ghi nhận lưu lượng local khi bạn đang kiểm tra.
3. Từ menu Kali Linux ở góc trên bên trái, gõ wire và nhấp vào wireshark.
4. Trong danh sách giao diện của Wireshark, nhấp đôi vào Loopback:lo. Điều này bắt đầu một phiên ghi nhận gói trên giao diện vòng lặp địa phương.
5. Trong cửa sổ terminal Kali Linux, gõ sudo hping3 -S 127.0.0.1 -a 1.2.3.4 -c 5. Lệnh này sẽ gửi năm gói tin tới 127.0.0.1 nhưng sẽ hiển thị địa chỉ IP nguồn (-a) là 1.2.3.4.
6. Chuyển lại về Wireshark. Nhận thấy có năm gói tin từ 1.2.3.4. Nhấp nút dừng màu đỏ để dừng ghi lại gói tin. Giữ Wireshark mở.
7. Quay lại cửa sổ terminal, gõ cd và nhấn Enter để chuyển đến thư mục home của người dùng hiện tại.
8. Tạo một tệp payload giả bằng cách gõ echo “This is nothing but fake data” > fake_payload.txt.
9. Gõ cat fake_payload.txt để xem nội dung tệp.
10. Quay lại Wireshark, từ menu File chọn File, Close, Continue without saving, sau đó nhấp đôi vào danh sách Loopback:lo để bắt đầu một phiên ghi nhận gói mới.
11. Chuyển về cửa sổ terminal.
12. Để gửi một gói hoàn toàn giả mạo, gõ sudo hping3 127.0.0.1 -a 1.2.3.4 -p 555 -d 500 --file fake_payload.txt. Lệnh này gửi 500 gói tin với kích thước 500 bytes có cổng đích là 555 từ nguồn 1.2.3.4, dùng tệp payload giả làm dữ liệu gói.
13. Chuyển về Wireshark và dừng ghi lại bằng cách nhấp nút dừng màu đỏ. Nhấp vào bất kỳ gói tin nào từ 1.2.3.4. Trong bảng ở giữa cạnh Transmission Control Protocol (TCP header), chú ý cổng đích được đặt là 555. Phía dưới ở bảng dữ liệu (bottom panel) sẽ thấy payload giả hiển thị trong dữ liệu gói.

