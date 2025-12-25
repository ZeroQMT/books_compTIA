# **Chapter 4 - Part 1: Create a Linux shell script and set it as executable**

1. Start and login to your Kali Linux virtual machine as user kali with a password of kali.
2. Type cd and press ENTER to change to the kali user home directory.
3. Create a script file using the nano text editor by typing nano scripttest.sh.
4. Enter (or copy and paste) the following shell script commands. You can paste in the Kali terminal windows from the Edit menu by choosing Paste Clipboard.

\#!/bin/bash

function show_ipinfo()
{
IP_VAR=`ifconfig eth0 | grep "inet" | tr -s ' ' | cut -d ' ' -f 3`
DGW_VAR=`ip route show | grep "default" | tr -s ' ' | cut -f 3 -d ' '`
echo "IP ADDRESS:" IPVARecho"DEFAULTGATEWAY:"*I**P**V*​*A**R**ec**h**o*"*D**EF**A**UL**TG**A**TE**W**A**Y*:"DGW_VAR
cat /etc/resolv.conf | grep "nameserver" | grep -v "#"
}

while true
do
clear
echo "UTILITY MENU"
echo "-------------"
echo "1 Show IP info"s
echo "2 whoami"
echo "3 Quit"
echo
echo "Enter choice:"
read selection
echo
case $selection in



​	1.show_ipinfo;;

2. whoami;;

3. clear; exit;;

​	esac

​	read junkvar

done



1. Press CTRL+X to exit. When prompted to "Save modified buffer?" press Y and press ENTER to accept the default filename.
2. Try to run the script by typing sudo ./scriptptest.sh. You will receive a "command not found" message because the script has not yet been set as executable.
3. Type chmod 550 scriptstest.sh to make the script readable (value of 4) and executable (value of 1) for the owner and group of the file.
4. Type ls -l scriptstest.sh. Notice the -r-x------ permissions listed twice; once for the owning user of the file, and once for the owning group of the file (both set to kali in this case).
5. Once again, attempt to run the script by typing sudo ./scriptstest.sh. This time the script runs. Press 3 to exit back to a shell prompt.



# **Ch4: Tạo một shell script Linux và gán quyền thực thi**

1. Bắt đầu và đăng nhập vào máy ảo Kali Linux của bạn với tư cách người dùng kali có mật khẩu là kali.
2. Gõ cd và nhấn ENTER để chuyển đến thư mục home của người dùng kali.
3. Tạo một file script bằng trình chỉnh sửa văn bản nano bằng cách gõ nano scripttest.sh.
4. Nhập (hoặc sao chép và dán) các lệnh shell script sau. Bạn có thể dán vào cửa sổ terminal Kali từ menu Edit bằng cách chọn Paste Clipboard.

```
#!/bin/bash

function show_ipinfo()
{
    IP_VAR=`ifconfig eth0 | grep "inet" | tr -s ' ' | cut -d ' ' -f 3`
    DGW_VAR=`ip route show | grep "default" | tr -s ' ' | cut -f 3 -d ' '`
    echo "IP ADDRESS:" $IP_VAR
    echo "DEFAULT GATEWAY:" $DGW_VAR
    cat /etc/resolv.conf | grep "nameserver" | grep -v "#"
}

while true
do
    clear
    echo "UTILITY MENU"
    echo "-------------"
    echo "1 Show IP info"
    echo "2 whoami"
    echo "3 Quit"
    echo
    echo "Enter choice:"
    read selection
    echo
    case $selection in
        1) show_ipinfo;;
        2) whoami;;
        3) clear; exit;;
        esac
done
```

1. Nhấn CTRL+X để thoát. Khi được nhắc “Save modified buffer?” hãy nhấn Y và nhấn ENTER để chấp nhận tên tập tin mặc định.
2. Thử chạy script bằng cách gõ sudo ./scriptptest.sh. Bạn sẽ nhận được thông báo "command not found" vì script chưa được gán quyền thực thi.
3. Gõ chmod 550 scriptptest.sh để làm cho script có thể đọc (4) và thực thi (1) cho chủ sở hữu và nhóm của file.
4. Gõ ls -l scriptptest.sh. Lưu ý quyền -r-x------ được liệt kê hai lần; một lần cho người dùng sở hữu file và một lần cho nhóm sở hữu file (ở đây đều là kali).
5. Một lần nữa, thử chạy script bằng cách gõ sudo ./scriptptest.sh. Lần này script sẽ chạy. Nhấn 3 để thoát về dòng lệnh.