# Ch 8: Managing Docker containers in Linux

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. View the current dictionary file that will be used to crack WPA2 passphrases by typing **sudo cat /usr/share/wordlists/rockyou.txt.** Press CTRL+C until the display of the file contents is interrupted and stops.
3. Change to the current user home directory by typing cd and pressing ENTER.
4. Type ls and notice the wpa-06.cap capture file. This file capture was captured on a WiFi network and contains the authentication traffic used by a valid client initially connecting to the WPA2 preshared key (PSK) network. Attackers will normally force existing clients to disconnect from the WiFi network thus forcing them to reconnect. This technique is called deauthentication.
5. Begin the attack by typing **sudo aircrack-ng wpa-06.cap -w /usr/share/wordlists/rockyou.txt**. After a few moments press CTRL+C to stop the attack (no passphrase is found).
6. You will now add a passphrase to the dictionary file used in the attack. Type **sudo nano /usr/share/wordlists/rockyou.txt.** At the top of the file type in (or copy from here) **2W433510228**: this is the actual WiFi passphrase; attackers normally use multiple dictionaries containing tens of millions of potential passphrases. Press CTRL+X, Y and press ENTER to save the change to the file.
7. Run the attack again by typing **sudo aircrack-ng wpa-06.cap -w /usr/share/wordlists/rockyou.txt**. This time notice the WPA2 passphrase is shown next to the text “KEY FOUND”. Bear in mind that this is an offline attack; intruder detection settings on the WiFi access point/router will not pick up on this attack.



# Ch 8: Quản lý các container Docker trên Linux

1. Bắt đầu và đăng nhập vào máy Kali Linux ảo của bạn với tư cách người dùng kali và mật khẩu kali.
2. Xem tệp từ điển hiện tại sẽ được dùng để phá các passphrase WPA2 bằng cách gõ sudo cat /usr/share/wordlists/rockyou.txt. Nhấn CTRL+C cho đến khi nội dung tệp bị ngắt hiển thị và dừng.
3. Thay đổi đến thư mục home của người dùng bằng cách gõ cd và nhấn ENTER.
4. Gõ ls và chú ý tệp capture wpa-06.cap. Tệp capture này được ghi lại từ một mạng WiFi và chứa lưu lượng xác thực được một máy client hợp lệ kết nối lần đầu với mạng WPA2 bằng khóa PSK. Hacker thường buộc các client hiện có ngắt kết nối khỏi mạng WiFi để buộc chúng kết nối lại. Kỹ thuật này được gọi là deauthentication.
5. Bắt đầu cuộc tấn công bằng cách gõ sudo aircrack-ng wpa-06.cap -w /usr/share/wordlists/rockyou.txt. Sau một vài phút, nhấn CTRL+C để dừng cuộc tấn công (không tìm thấy mật khẩu).
6. Bạn sẽ thêm một mật khẩu vào tệp từ điển được dùng trong cuộc tấn công. Gõ sudo nano /usr/share/wordlists/rockyou.txt. Ở đầu tệp gõ vào (hoặc sao chép từ đây) 2W433510228: đây là mật khẩu WiFi thực tế; những kẻ tấn công thường dùng nhiều từ điển chứa hàng chục triệu mật khẩu tiềm năng. Nhấn CTRL+X, Y và ENTER để lưu thay đổi vào tệp.
7. Chạy lại cuộc tấn công bằng cách gõ sudo aircrack-ng wpa-06.cap -w /usr/share/wordlists/rockyou.txt. Lần này lưu ý mật khẩu WPA2 được hiển thị bên cạnh chữ “KEY FOUND”. Lưu ý rằng đây là một cuộc tấn công offline; cài đặt phát hiện xâm nhập trên điểm truy cập WiFi sẽ không phát hiện cuộc tấn công này.