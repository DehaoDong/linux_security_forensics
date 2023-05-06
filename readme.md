主要模块(main modules)：
1. 用户信息获取(storing information of users)
2. 系统重要文件备份(backing up important system files)
3. alias检测(alias check)
4. 后门检测(backdoors check)
5. ssh检测(ssh check)
6. 登录日志检测(login logs check)
7. 网络连接检测(network connections check)
8. 进程检测(processes check)
9. 启动项检测(startups check)
10. 用户历史操作检测(user history operations check)
11. 网络服务器检测(web severs check)
12. 文件检测(files check)
13. app包检测(app packages check)

取证内容：
1. 启动项
2. 重要系统文件
3. aliases
4. 所有软件包
5. 网络连接
6. 本机信息
7. 进程详情
8. ssh日志
9. 用户信息
10. *所有可疑项目汇总

检测模块原理：
1. alias：
    获取所有用户的所有别名(alias)列表。
    遍历所有的别名，并对每一个别名进行以下检查：
    a. 确保别名命令具有正确的引号，即以单引号包括整个命令。
    b. 检查别名命令是否修改了系统命令，即别名命令和系统命令名不同。
    c. 检查别名命令是否包含导出环境变量的语句。
    d. 检查别名命令是否包含输出重定向符号 ">"。
2. 后门：
    环境变量后门：检查是否存在恶意的环境变量，如 LD_PRELOAD、LD_AOUT_PRELOAD、LD_ELF_PRELOAD、LD_LIBRARY_PATH 和 PROMPT_COMMAND。
    ld.so.preload 后门：检查是否存在 /etc/ld.so.preload 文件，该文件中包含了恶意代码，被用于加载额外的共享库。
    Cron 后门：检查是否存在恶意的 Cron 任务，这些任务在指定的时间点运行，并且可能包含了恶意的命令['rm -rf', 'wget', 'curl', 'nc']。
    SSH 后门：检查是否存在 SSH 后门，如是否有非 root 用户通过 SSH 登录系统，或者是否存在被恶意代码替换的 sshd 二进制文件。
    inetd 后门：检查是否存在 inetd 后门，如是否存在 echo、discard、chargen、daytime 或 time 等服务。
    setuid 后门：检查是否存在 setuid 后门，即在 root 权限下运行，但存在安全漏洞或被恶意代码替换的二进制文件。
3. ssh：
    读取系统日志文件 /var/log/auth.log 或 /var/log/secure（取决于系统类型）中包含 SSH 登录信息的行，并分析每个登录尝试的来源 IP、
    登录用户、登录时间等信息。对于登录失败的记录，程序会记录 IP 和失败次数；对于登录成功的记录，程序会判断该 IP 的登录失败次数是否超过设定的
    阈值，如果超过，则认为该登录尝试可能存在异常行为。
4. 登录日志：
    包括wtmp、utmp和lastlog。提取其中的登录信息，解析出IP地址，并使用GeoLite2数据库判断IP地址的来源是否为境外。
5. 网络连接：
    使用 psutil 库获取所有网络连接的详细信息，包括本地 IP 地址、本地端口、远程 IP 地址、远程端口、状态和进程 ID 等。
    使用GeoLite2数据库判断IP地址的来源是否为境外。
    通过读取AlienVault Open Threat Exchange数据库加载恶意 IP 地址列表，检测活动连接是否涉及这些 IP，以确定是否存在可疑活动。
6. 进程：
    检查CPU和内存使用率异常的进程。如果进程的CPU或内存使用率超过给定的阈值（默认为90%），则将其视为异常。
    检测隐藏进程。通过比较ps命令和/proc目录中的进程列表，找出在ps命令中未显示的隐藏进程。
    检测反弹shell类进程。通过查找进程命令行参数中的特定关键字（bash /dev/tcp/ nc等），找出可能是反弹shell的进程。
    检查源文件已被删除的进程。通过检查进程的可执行文件路径（/proc/{pid}/exe），找出源文件已被删除的进程。
7. 启动项：
    确定当前系统的 init 系统类型。该函数使用 ps 命令获取 PID 为 1 的进程的名称，以确定系统的 init 系统类型。支持的 init 系统类型包括 
    SysV、Systemd 和 Upstart。
    a. 如果系统的 init 系统类型为 Systemd，则使用 systemctl list-unit-files --type=service 命令获取当前所有的 Systemd 服务，并将其
    名称存储在一个列表中。接着，程序对每个服务使用 journalctl -u service-name 命令备份其日志文件，并对其配置文件进行备份。
    b. 如果系统的 init 系统类型为 SysV，则使用 glob 模块获取所有的 SysV 启动项脚本，并将其名称存储在一个列表中。接着，程序对每个启动项备份其
    相应的日志文件，并对其配置文件进行备份。
    c. 如果系统的 init 系统类型为 Upstart，则使用 glob 模块获取所有的 Upstart 配置文件，并将其名称存储在一个列表中。接着，程序对每个启动项
    备份其相应的日志文件，并对其配置文件进行备份。
8. 历史操作：
    检测用户在系统中的历史操作记录，包括境外IP操作和反弹shell操作。
    a. 获取所有用户的主目录，并获取每个用户的.bash_history文件，这些文件包含了用户在命令行中输入的历史命令。
    b. 针对这些历史命令进行正则表达式匹配，以检测是否存在境外IP操作和反弹shell操作。
    c. 在检测境外IP操作时，使用GeoIP2库中的Reader类，读取IP地理位置数据库，然后对每个历史命令进行匹配，并检查IP是否为境外IP。
    d. 在检测反弹shell操作时，使用正则表达式匹配nc、netcat、socat和bash等关键字，并提取出IP地址和端口号。
9. 服务器：
    备份服务器日志和检查web服务器是否存在WebShell。
    a. 在备份服务器日志的部分，从server_logs中读取所有服务器的日志目录路径，然后遍历每个目录，备份所有以.log结尾的文件到指定目录下。
    b. 在检查web服务器是否存在WebShell的部分，程序首先从server_directories读取所有服务器的web目录路径，然后遍历每个目录，
    查找所有以.php、.aspx、.jsp、.pl结尾的文件，对于每个文件，程序读取文件内容，并与预定义的WebShell特征列表中的每个特征进行比较.
10. 文件：
    系统文件可执行性扫描和临时目录文件安全扫描。
    在系统文件可执行性扫描中，使用os模块的walk()函数遍历指定路径下的所有文件，判断每个文件是否可执行，如果不可执行，则将该文件路径记录到输出结果中。
    在临时目录文件安全扫描中，使用os模块的walk()函数遍历指定路径下的所有文件，采用两种方式进行检测：
            检查具有可执行性的临时文件，如果一个文件同时拥有读、写、执行权限，就可能会被黑客用于进行攻击。
            检查临时文件的大小，如果一个文件过大，可能会引起磁盘空间耗尽或拒绝服务攻击等问题。
11. app包：
    获取可用的包管理器以及已安装的软件包。首先定义了一个包含不同包管理器的列表，包括dpkg（Debian/Ubuntu等），rpm（Red Hat/Fedora等）
    和pacman（Arch Linux等）。
    验证已安装软件包的完整性。对于已安装的每个软件包，运行验证命令来检查其完整性。




未完成的工作：
1. 对抗系统劫持（将项目静态编译）
2. rootkit检测