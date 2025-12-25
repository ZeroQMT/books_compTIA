# **Chapter 2: Enable SSH public key authentication on a Linux host**

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Start the SSH daemon by typing **sudo service ssh start.**
3. Open another terminal window and type **ssh localhost -l kali.** When asked to continue connecting, type yes and press ENTER. Enter kali for the user password. You are now logged in via SSH using username and password. Type exit.
4. You will now configure SSH public key authentication. Enter **ssh-keygen** to generate a unique public and private key pair. Press ENTER to accept the default location and filename for the private key file. Enter kali as the passphrase twice to confirm. For production environments always follow organization password policy requirements.
5. Type cd and press ENTER to change the current user home directory.
6. Type **cd .ssh** to change to the hidden ssh dir. Type **ls** to list files; notice the private key file (id_rsa) and the public key file (id_rsa.pub).
7. When creating key pairs on other hosts, you must copy the user public key file to the server, specifically, the authorized_keys file in the user .ssh folder. Even though we generated the keys on the SSH server (localhost IP of 127.0.0.1), we will step through how this works. Type **ssh-copy-id -i ~/.ssh/id_rsa.pub kali@127.0.0.1.** When asked to trust the SSH server fingerprint, type yes and press ENTER.
8. Enter is and notice the authorized_keys file that the ssh-copy-id command created and copied the public key file to. The ssh-copy-id command also sets the necessary permissions for user access (and nobody else!) to the file.
9. View the copied public key by typing **cat authorized_keys.** The public key must reside on the server and the private key is on the connecting user station (same computer this example).
10. In another terminal window type **ssh localhost -l kali** again to login as user kali. This time you are asked for the SSH private passphrase (and not the user password). Enter kali. You are now logged in using SSH public key authentication.



# **Chapter 2: Bật xác thực khóa công khai SSH trên một máy Linux mục tiêu**

1. Bắt đầu và đăng nhập vào máy ảo Kali Linux của bạn với tư cách người dùng kali có mật khẩu là kali.
2. Khởi động daemon SSH bằng cách nhập **sudo service ssh start.**
3. Mở một cửa sổ terminal khác và gõ **ssh localhost -l kali.** Khi được hỏi có tiếp tục kết nối hay không, gõ yes và nhấn ENTER. Nhập kali làm mật khẩu người dùng. Bạn bây giờ đã đăng nhập qua SSH bằng tên người dùng và mật khẩu. Gõ exit để thoát.
4. Bây giờ bạn sẽ cấu hình xác thực khóa công khai SSH. Nhập **ssh-keygen** để sinh một cặp khóa công khai và khóa riêng duy nhất. Nhấn ENTER để chấp nhận vị trí và tên file mặc định cho khóa riêng. Nhập kali làm passphrase hai lần để xác nhận. Đối với môi trường sản phẩm, luôn tuân thủ yêu cầu chính sách mật khẩu của tổ chức.
5. Gõ cd và nhấn ENTER để chuyển thư mục người dùng hiện tại.
6. Gõ cd .ssh để chuyển đến thư mục ẩn ssh. Gõ **ls** để liệt kê các tập tin; lưu ý đến tập tin khóa riêng (id_rsa) và tập tin khóa công khai (id_rsa.pub).
7. Khi tạo cặp khóa trên các hosts khác, bạn phải sao chép tập tin khóa công khai của người dùng lên máy chủ, cụ thể là tập tin authorized_keys trong thư mục .ssh của người dùng. Mặc dù ta đã sinh khóa trên máy SSH (localhost với IP 127.0.0.1), ta sẽ đi qua cách hoạt động. Gõ **ssh-copy-id -i ~/.ssh/id_rsa.pub kali@127.0.0.1.** Khi được hỏi có tin cậy khóa máy chủ SSH hay không, gõ yes và nhấn ENTER.
8. Nhập is và chú ý tập tin authorized_keys được lệnh ssh-copy-id tạo ra và sao chép khóa công khai vào. Lệnh ssh-copy-id cũng thiết lập các quyền cần thiết cho quyền truy cập của người dùng (và không cho ai khác) vào tập tin.
9. Xem khóa công khai đã sao chép bằng cách gõ **cat authorized_keys.** Khóa công khai phải ở trên máy chủ và khóa riêng ở phía máy kết nối (cùng máy tính với ví dụ này).
10. Trong một cửa sổ terminal khác, gõ **ssh localhost -l** kali một lần nữa để đăng nhập với tư cách người dùng kali. Lần này bạn sẽ được yêu cầu nhập passphrase khóa riêng SSH (và không phải mật khẩu người dùng). Nhập kali. Bạn bây giờ đã đăng nhập bằng xác thực SSH khóa công khai.