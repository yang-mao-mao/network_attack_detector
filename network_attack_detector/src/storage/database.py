
from __future__ import annotations

import sqlite3
from pathlib import Path


class Database:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    category TEXT NOT NULL,
                    level TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    rule_id TEXT,
                    rule_name TEXT,
                    evidence TEXT,
                    description TEXT,
                    suggestion TEXT,
                    packet_id TEXT,
                    extra_json TEXT
                );

                CREATE TABLE IF NOT EXISTS packets (
                    packet_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    payload_preview TEXT,
                    raw_summary TEXT
                );
                """
            )


#当前重点，完善SQLite数据库的初始化和连接功能。
#数据库中希望存储：告警信息和数据包信息。
#1.根据路径在磁盘上开辟空间
#2.将棋盘上的文件与数据库关联起来
#3.创建数据库表格
'''
import sqlite3
from pathlib import Path
class Database:
    # 数据库的初始化，__init__方法接收一个字符串类型（或者Path类），
    # 并且保证磁盘上的文件目录是存在的
    def __init__(self,db_path:str|Path) ->None:
        self.db_path==Path(db_path)
        self.db_path.parent.mkdir(parents=True,exist_on=True)
    #  将磁盘上实际存在的文件与sqlite3数据库连接起来，就可以以操作数据库的方式操作文件
    # （前提是文件需要以sqlite3的形式初始化）
    def connect(self)->sqlite3.Connection:
        conn=sqlite3.connect(self.db_path)
        conn.row_factory=sqlite3.Row
        return conn
    def initialize(self)->None:
        with self.connect() as conn:
            #sqlite3数据类型：NULL,INTEGER(整型)，REAL（浮点型），TEXT（文本类型），BLOB（二进制类型，图片，电影）
            conn.executescript(
                """
                create table if not exists alerts(
                    
                    alert_id TEXT primary key,
                    timestamp REAl,
                    category TEXT not NULL,
                    level TEXT not NUll,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTERGER,
                    protocol TEXT,
                    rule_id TEXT,
                    rule_name TEXT,
                    evidence TEXT,
                    description TEXT,
                    suggestion TEXT,
                    packet_id TEXT,
                    extra_json TEXT
                );
                create table if not exists packets(
                    packet_id TEXT primary key,
                    timestamp REAL not NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    payload_preview TEXT,
                    raw_summary TEXT
                );

                """
            )
 '''   



    

        



