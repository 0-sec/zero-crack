# zero-crack - webapps crack tools
Web应用(webapps)暴力破解小工具,用于一键爆破常见Web应用(e.g. tomcat weblogic nexus),zero-crack内置了各组件的常用或默认登录组合,若不指定用户名和密码字典则使用内置字典,zero-crack默认会根据各webapps的登录策略设定延时,例如tomcat默认为:"同一个账户登录失败5次之后锁定5分钟"

# install
```bash
git clone https://github.com/0-sec/zero-crack
# 安装所需的 python 依赖
pip3 install -r requirements.txt
# Linux & MacOS & Windows
python3 zero-crack.py -u http://127.0.0.1:8000 -a tomcat
```

# optons
```
  -u URL, --url URL     target URL (e.g. -u "http://example.com")
  -a APP                specify apps (e.g. -a "tomcat")
  -l USERNAME [USERNAME ...]
                        username (e.g. -l "admin")
  -L USERLIST           username file (e.g. -L "user.txt")
  -p PASSWORD [PASSWORD ...]
                        password (e.g. -l "admin")
  -P PASSLIST           passowrd file (e.g. -P "pass.txt")
  --delay DELAY         delay time, default 0s
  -h, --help            show this help message and exit
```

# examples
```
python3 zero-crack.py -u http://127.0.0.1:8000 -a tomcat
python3 zero-crack.py -u http://127.0.0.1:8000 -a tomcat -l admin -p admin
python3 zero-crack.py -u http://127.0.0.1:8000 -a tomcat -L user.txt -P pass.txt
```

# demo
![image](https://user-images.githubusercontent.com/32918050/117906460-8906cf80-b307-11eb-8d51-27d717ec2e33.png)

# todo
* ✔ tomcat
* ✔ weblogic
* wordpress
* nexus
* activemq
* jenkins
* ... ...


