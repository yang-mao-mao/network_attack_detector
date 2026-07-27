#目标是建立数据库，用于储存alert和packet(并不储存完整原始数据包)
#定义一个database类
#三步走：
#1.在硬盘上开辟一块空间，pathlib
#2.建立连接，conn
#3.定义数据库

import sqlite3
from pathlib import Path

class Database:
    #新建数据库时只需要数据库的地址
    def __init__(self,db_path:str|Path)->None:
        self.db_path=Path(db_path)#使用Path方便快捷地管理地址和文件目录操作
        self.db_path.parent.mkdir(parents=True,exist_ok=True)#因为数据库最后是一个文件，所以应该先确保文件的父目录存在
    
    #建立连接，调用sqlite3.connect("path")创建一个连接
    #设置访问格式,这样就可以以列名为参数读取数据了。例：ret['name']
    def connect(self)->sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory=sqlite3.Row
        return conn
        
    #初始化数据库的格式，这里不需要游标
    #一般而言，打开文件或者操作数据库的时候（这些情景都涉及资源的释放），可以使用with块，能够在代码执行结束之后自动为我们释放资源
    def initialize(self)->None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists `alerts`(
                    alert_id TEXT primary key,
                    timestamp  REAL not null,
                    category  TEXT not null,
                    level  TEXT not null,
                    src_ip  TEXT ,
                    dst_ip  TEXT,
                    src_port  INTEGER,
                    dst_port  INTEGER,
                    protocol  TEXT,
                    rule_id  TEXT,
                    rule_name  TEXT,
                    evidence  TEXT,
                    description  TEXT,
                    suggestion  TEXT,
                    packet_id  TEXT,
                    extra_json  TEXT
                
                );
                create table if not exists `packets`(
                        packet_id  TEXT primary key,
                        timestamp  REAL not null,
                        src_ip  TEXT ,
                        dst_ip  TEXT,
                        src_port  INTEGER,
                        dst_port  INTEGER,
                        protocol  TEXT,
                        length  INTEGER,
                        payload_preview TEXT,
                        raw_summary  TEXT
                )
                
                """
            )






