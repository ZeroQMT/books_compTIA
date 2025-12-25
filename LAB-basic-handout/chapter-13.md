# Chapter 13: Use the Autopsy Forensic Browser tool in Kali Linux

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. From a terminal window, type **sudo autopsy**. This will start autopsy and present a message (such as http://localhost:9999/autopsy) stating how to connect to Autopsy from a web browser.
3. Right-click the listed http link and choose **Open Link**. This will take you to the local autopsy web page.
4. At the bottom center of the web page, click **New Case**. For the case name type **Case1,** then fill in fictitious description and investigator names. Click **New Case** at the bottom left.
5. Click **Add Host**. Enter a fictitious host name and click the Add Host button at the bottom left.
6. Click **Add Image**, then **Add Image File.**
7. For **1. Location, type /home/kali/samplepartition.img**. This is a sample disk partition image file of a Window NTFS file system.
8. For **2. Type**, choose **Partition**. Click **Next**.
9. Choose **Calculate the hash value for this image.** Click **Add.**
10. Once the MD5 hash is calculated, click OK, then click **Analyze**, then click **File Analysis.**
11. In the right panel, scroll down and click the del1 folder listing.
12. Notice **file6.jpg** shows as red because the file is deleted.
13. Click **file6.jpg** to view the file contents in the lower panel.
14. In the middle panel, click the **Export** link to save the jpg file as a standalone file. Click **Save File** then click OK.
15. Click the folder icon in the upper left of the screen. Navigate to the Downloads folder in the Kali home directory.
16. Double-click the jpg file to ensure it opens.





# Chapter 13: Sử dụng công cụ Autopsy Forensic Browser trong Kali Linux

1. Khởi động và đăng nhập vào máy ảo Kali Linux của bạn với tư cách người dùng kali và mật khẩu kali.
2. Từ cửa sổ terminal, gõ sudo autopsy. Lệnh này sẽ khởi động Autopsy và hiển thị một thông điệp (như http://localhost:9999/autopsy) cho biết cách kết nối tới Autopsy từ trình duyệt web.
3. Click chuột phải lên liên kết http được liệt kê và chọn Open Link. Thao tác này đưa bạn đến trang web Autopsy tại máy (local).
4. Ở giữa dưới của trang web, nhấn New Case. Đặt tên cho vụ án là Case1, sau đó điền mô tả và tên điều tra viên (tạm thời). Nhấn New Case ở phía dưới bên trái.
5. Nhấn Add Host. Nhập tên máy chủ giả và nhấn Add Host ở phía dưới bên trái.
6. Nhấn Add Image, sau đó Add Image File.
7. Với 1. Location, gõ /home/kali/samplepartition.img. Đây là một file ảnh phân vùng đĩa mẫu có hệ thống file NTFS của Windows.
8. Với 2. Type, chọn Partition. Nhấn Next.
9. Chọn Calculate the hash value for this image. Nhấn Add.
10. Khi hash MD5 được tính xong, nhấn OK, sau đó nhấn Analyze, rồi nhấn File Analysis.
11. Ở bảng bên phải, cuộn xuống và nhấp vào thư mục del1 để xem danh sách.
12. Lưu ý file6.jpg xuất hiện màu đỏ do bị xóa.
13. Nhấp vào file6.jpg để xem nội dung file ở bảng phía dưới.
14. Ở bảng giữa, nhấn Export để lưu file jpg thành một file độc lập. Nhấn Save File rồi nhấn OK.
15. Nhấn biểu tượng thư mục ở góc trên bên trái màn hình. Điều hướng đến thư mục Downloads trong thư mục home của Kali.
16. Nhấp đúp vào file jpg để đảm bảo nó mở được.

