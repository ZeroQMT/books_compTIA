# **Ch5: Crack Linux passwords using John the Ripper**

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Type **cd /usr/share/wordlists**, then **ls**. Notice the rockyou.txt file. On a fresh Kali Linux machine you might have to unzip the password file using a command such as **sudo gunzip rockyou.txt.gz**, but in the exercise we will use the supplied rockyou.txt file.
3. View the contents of the file by typing **cat rockyou.txt**. Press CTRL+C to stop the scrolling.
4. Change to your user home directory by typing **cd** and pressing ENTER.
5. Copy the contents of the Linux user account and password file to a single file using the **sudo unshadow /etc/passwd /etc/shadow > credfile.txt**
6. Enter **sudo john --wordlist=/usr/share/wordlists/rockyou.txt credfile.txt** to try to crack password hashes in the Linux /etc/shadow file.
7. Enter **sudo john --show credfile.txt**. Notice the passwords for the kali user and for account uone (created in an earlier exercise) are shown in plaintext.





# **Ch5: Cracking mật khẩu Linux bằng John the Ripper**

1. Bắt đầu và đăng nhập vào máy Kali Linux ảo của bạn với tư cách người dùng kali có mật khẩu là kali.
2. Gõ cd /usr/share/wordlists, sau đó gõ ls. Nhìn thấy tập tin rockyou.txt. Trên một máy Kali Linux mới, bạn có thể phải giải nén tập tin mật khẩu bằng lệnh như sudo gunzip rockyou.txt.gz, nhưng trong bài tập này chúng ta sẽ dùng tập tin rockyou.txt được cung cấp.
3. Xem nội dung của tập tin bằng cách gõ cat rockyou.txt. Nhấn CTRL+C để dừng cuộn.
4. Chuyển đến thư mục home của người dùng bằng cách gõ cd và nhấn ENTER.
5. Sao chép nội dung của tài khoản người dùng Linux và tập tin mật khẩu sang một tập tin duy nhất bằng lệnh sudo unshadow /etc/passwd /etc/shadow > credfile.txt
6. Nhập sudo john --wordlist=/usr/share/wordlists/rockyou.txt credfile.txt để thử crack các hash mật khẩu trong tập tin /etc/shadow.
7. Nhập sudo john --show credfile.txt. Lưu ý mật khẩu của người dùng kali và tài khoản uone (tạo ở bài tập trước) được hiển thị ở dạng văn bản thuần.