# **Chapter 5: Configure Software RAID in Linux**

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Enter **sudo lsblk --scsi** to list SCSI disk block devices. You should see sda, sdb, and sdc disk devices. These are three separate disks. We will create a disk mirror between sdb and sdc.
3. Enter **sudo fdisk /dev/sdb** and press ENTER. Press n (new partition), and then press ENTER four times to create a primary partition that consumes the entire disk.
4. Press **t** to change the partition type, and then enter **fd** to set the type to Linux raid autodetect.
5. Press **w** to write the changes to disk.
6. Repeat steps 4–6 in this exercise, except enter **sudo fdisk /dev/sdc instead of sudo fdisk /dev/sdb.**
7. Enter **sudo fdisk -l /dev/sdb /dev/sdc** to verify that the Linux RAID autodefed partition flag has been set on both disk partitions (look under the Type heading). Notice the partitions are /dev/sdb1 and /dev/sdc1 (look under the Device heading).
8. Install the mdadm software RAID tool by typing **sudo apt-get install mdadm.**
9. Create a software RAID 1 (mirroring) configuration by typing **sudo mdadm --create /dev/md1 --level=1 --raid-devices=2 /dev/sdb1 /dev/sdc1.** Take note of the double dashes (--) before the recreate and raid-devices parameters.
10. Press **Y** (for yes, to continue creating the array).
11. Verify your work by typing **sudo mdadm --detail /dev/md1**. In the bottom right under the State column you should see “active sync” for each of the mirrored disk partitions /dev/sdb1 and /dev/sdc1.
12. Make a mount directory by typing **sudo mkdir /cust_trans.**
13. Format the file system by typing **sudo mkfs -t ext4 /dev/md1**. Mount the file system to a directory so it is ready to use by typing **sudo mount /dev/md1 /cust_trans.** Files can now be added to /cust_trans folder as you normally would with any folder, the difference is that now a copy of each file will be mirrored to a second disk partition.
14. Enter the following command to verify the /cust_trans mount point is using the disk mirror device /dev/md1: **sudo mount | grep /dev/md1**



# Ch5: Cấu hình RAID phần mềm trong Linux

1. Khởi động và đăng nhập vào máy ảo Kali Linux của bạn với tư cách người dùng kali có mật khẩu là kali.
2. Gõ sudo lsblk --scsi để liệt kê các thiết bị đĩa block SCSI. Bạn nên thấy các đĩa sda, sdb và sdc. Đây là ba đĩa riêng biệt. Chúng ta sẽ tạo một mảng sao chép (mirror) giữa sdb và sdc.
3. Gõ sudo fdisk /dev/sdb và nhấn ENTER. Nhấn n (partition mới), rồi nhấn ENTER bốn lần để tạo một phân vùng chính chiếm toàn bộ đĩa.
4. Nhấn t để đổi loại phân vùng, rồi nhập fd để đặt loại thành Linux raid autodetect.
5. Nhấn w để ghi các thay đổi lên đĩa.
6. Lặp lại các bước 4–6 trong bài tập này, ngoại trừ gõ sudo fdisk /dev/sdc thay vì sudo fdisk /dev/sdb.
7. Nhập sudo fdisk -l /dev/sdb /dev/sdc để xác nhận rằng cờ phân vùng được tự động nhận diện RAID của Linux đã được đặt ở cả hai phân vùng đĩa (xem dưới tiêu đề Type). Chú ý các phân vùng là /dev/sdb1 và /dev/sdc1 (xem dưới cột Device).
8. Cài đặt công cụ RAID mdadm bằng cách gõ sudo apt-get install mdadm.
9. Tạo cấu hình RAID 1 (mirroring) bằng cách gõ sudo mdadm --create /dev/md1 --level=1 --raid-devices=2 /dev/sdb1 /dev/sdc1. Lưu ý sự xuất hiện của hai dấu gạch ngang (--) trước các tham số recreate và raid-devices.
10. Nhấn Y để tiếp tục tạo mảng.
11. Xác thực công việc bằng cách gõ sudo mdadm --detail /dev/md1. Ở góc dưới bên phải, dưới cột State, bạn sẽ thấy “active sync” cho từng phân vùng đĩa sao chép /dev/sdb1 và /dev/sdc1.
12. Tạo thư mục gắn kết bằng cách gõ sudo mkdir /cust_trans.
13. Định dạng hệ thống tập tin bằng cách gõ sudo mkfs -t ext4 /dev/md1. Gắn hệ thống tập tin vào một thư mục để sẵn sàng sử dụng bằng cách gõ sudo mount /dev/md1 /cust_trans. Bây giờ bạn có thể thêm file vào thư mục /cust_trans như bình thường; khác biệt là mỗi file được sao chép sang đĩa kia ở phân vùng đĩa khác.
14. Nhập lệnh sau để xác thực rằng điểm gắn /cust_trans đang sử dụng thiết bị mirror đĩa /dev/md1: sudo mount | grep /dev/md1