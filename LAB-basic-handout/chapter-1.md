# **Chapter 1: Wiping a Disk Using the dd Command**

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Open a terminal window.
3. Type **sudo fdisk -l**. You will be prompted to enter the password for kali. Enter kali and press ENTER.
4. Notice the device listing for /dev/sdb. The OS is running from /dev/sda; sda has multiple partitions listed such as sda1, sda2 and so on.
5. Create and format a disk partition on /dev/sdb with the following commands:
   1. **sudo fdisk /dev/sdb**
   2. Type **n** for new partition
   3. Type **p** for primary
   4. Press ENTER to accept the rest of the defaults until you return to the Command (m for help): prompt.
   5. Press w to write the changes to disk.
6. Format the new partition by typing **sudo mkfs -t ext4 /dev/sdb1.**
7. Create a mount point directory for the newly created disk partition by typing **sudo mkdir /datavol.**
8. Mount the disk partition in the newly created folder by typing **sudo mount /dev/sdb1 /datavol.**
9. Create some sample text files by typing **sudo touch /datavol/file{1,2,3}.txt.**
10. View the files by typing **sudo ls /datavol.**
11. Now wipe the new disk partition by filling it with random data. Type **sudo dd if=/dev/urandom of=/dev/sdb1.** This will take a few minutes to complete.
12. Type **sudo ls /datavol;** this time the sample text files are not listed; the partition has been wiped.
13. Type **sudo umount /dev/sdb1** to unmount the wiped disk partition.



# **Chương 1: Xóa sạch đĩa bằng lệnh dd**

1. Đăng nhập vào máy ảo Kali Linux với tư cách người dùng kali và mật khẩu là kali.
2. Mở một cửa sổ terminal.
3. Gõ **sudo fdisk -l.** Bạn sẽ được yêu cầu nhập mật khẩu cho user kali. Nhập kali và nhấn ENTER.
4. Lưu ý danh sách thiết bị /dev/sdb. Hệ điều hành đang chạy từ /dev/sda; sda có nhiều phân vùng như sda1, sda2 và cứ thế.
5. Tạo và định dạng một phân vùng đĩa trên /dev/sdb với các lệnh sau:
   1. sudo fdisk /dev/sdb
   2. Gõ n để tạo phân vùng mới
   3. Gõ p để tạo phân vùng chính (primary)
   4. Nhấn ENTER để chấp nhận các giá trị mặc định còn lại cho đến khi quay lại nhắc lệnh: prompt (m for help)
   5. Nhấn w để ghi các thay đổi vào đĩa.
6. Định dạng phân vùng mới bằng cách gõ **sudo mkfs -t ext4 /dev/sdb1.**
7. Tạo thư mục điểm mount cho phân vùng đĩa được tạo mới bằng cách gõ **sudo mkdir /datavol.**
8. Gắn (mount) phân vùng đĩa vào thư mục đã tạo bằng cách gõ **sudo mount /dev/sdb1 /datavol.**
9. Tạo một số tập tin văn bản mẫu bằng cách gõ **sudo touch /datavol/file{1,2,3}.txt.**
10. Xem các tập tin bằng cách gõ **sudo ls /datavol.**
11. Bây giờ xóa sạch phân vùng đĩa mới bằng cách lấp đầy dữ liệu ngẫu nhiên. Gõ **sudo dd if=/dev/urandom of=/dev/sdb1**. Việc này sẽ mất vài phút để hoàn tất.
12. Gõ **sudo ls /datavol;** lần này các tập tin mẫu không còn được liệt kê nữa; phân vùng đã bị xóa.
13. Gõ **sudo umount /dev/sdb1** để unmount phân vùng đĩa đã bị xóa.