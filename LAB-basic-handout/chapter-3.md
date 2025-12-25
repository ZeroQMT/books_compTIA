# **Chapter 3: Create a Linux User and Group**

1. Start and login to your Kali Linux virtual machine as user kali with a password of **kali.**
2. To create a group, type **sudo groupadd hq_admins.** If prompted, enter kali for the password.
3. Type **tail** **/etc/group** to view the last few lines of the file. Notice the hq_admins group is created and has been assigned a group id.
4. To create a user account with a home directory and as a member of the hq_admins group, type **sudo useradd ufour -m -g hq_admins.**
5. Set the password for ufour by typing **sudo passwd ufour**. Enter kali as the password twice. For production environments always follow organization password policy requirements.
6. Type **sudo tail /etc/passwd** to view the last few lines of the file. Notice ufour is listed as a valid user.
7. Type **sudo tail /etc/shadow** to view the last few lines of the file. Notice ufour is listed with password expiry information and the password hash for ufour.
8. Login as ufour by typing **su - ufour** (su means “switch user”. The dash means to perform a full login and to run login scripts, etc.)
9. Type **whoami** to verify you are logged in as ufour. Type **exit.**



# **Chapter 3: Tạo người dùng và nhóm trên Linux**

1. Bắt đầu và đăng nhập vào máy Kali Linux ảo của bạn với tư cách người dùng kali có mật khẩu là **kali.**
2. Để tạo một nhóm, gõ **sudo groupadd hq_admins.** Nếu được nhắc, nhập kali làm mật khẩu.
3. Gõ **tail /etc/group** để xem vài dòng cuối của tệp. Lưu ý nhóm hq_admins được tạo và đã có một Id nhóm (GID).
4. Để tạo một tài khoản người dùng có thư mục home và là thành viên của nhóm hq_admins, gõ **sudo useradd ufour -m -g hq_admins.**
5. Đặt mật khẩu cho ufour bằng cách gõ **sudo passwd ufour.** Nhập kali làm mật khẩu hai lần. Đối với môi trường sản phẩm, luôn tuân thủ yêu cầu chính sách mật khẩu của tổ chức.
6. Gõ **sudo tail /etc/passwd** để xem vài dòng cuối của tệp. Lưu ý ufour được liệt kê là một người dùng hợp lệ.
7. Gõ **sudo tail /etc/shadow** để xem vài dòng cuối của tệp. Lưu ý ufour được liệt kê với thông tin hết hạn mật khẩu và băm mật khẩu cho ufour.
8. Đăng nhập vào ufour bằng cách gõ **su - ufour** (su có nghĩa là “switch user”. Dấu gạch ngang có nghĩa là thực hiện đăng nhập đầy đủ và chạy các script đăng nhập, v.v.)
9. Gõ **whoami** để xác minh bạn đang đăng nhập với tư cách ufour. Gõ exit để thoát.