#该文件的目的是实现告警信息alert的存储
#database_yang.py中已经实现了数据库的建立和连接的建立

from __future__ import annotations#无脑加上，使类型注释以字符串形式保存，使编译时不报错

import json
import sqlite3

#想要存储数据，需要数据类型，需要数据库
from ..core.models import Alert
from ..core.models import AttackCategory,AlertLevel,Protocol
from .database import Database


#实现一个类，它的功能是将告警信息转为json类型，然后存入数据库
#思路分歧：是写一个函数，每条数据存入的时候都调用这个函数；还是为每个数据库写一个类，在类中实现写入数据的方法

class AlertRepository:
    #关于语法，实际上python类的实例化是调用了__new__方法，__init__方法实际上只是用于修改属性，这样自然无需返回值
    #初始化里应该建立好连接？实际上新建数据库类实例的时候应该已经初始化完了
    #应该实现：1.存入新纪录  2.查询最近记录   3.查询所有记录   4.根据id查询记录
    def __init__(self,database:Database)->None:
        self.database=database
    
    def save(self,alert:Alert)->None:
        with self.database.connect() as conn:
            conn.execute(
                """
                insert or replace into `alerts`(
                    `alert_id`,`timestamp`,`category`,`level`,`src_ip`,`dst_ip`,`src_port`,`dst_port`,`protocol`,
                    `rule_id`,`rule_name`,`evidence`,`description`,`suggestion`,`packet_id`,`extra_json`
                )   values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   
                """,
                (
                    alert.alert_id,
                    alert.timestamp,
                    alert.category.value,#原本是枚举类，所以要把值取出来
                    alert.level.value,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.src_port,
                    alert.dst_port,
                    alert.protocol.value,
                    alert.rule_id,
                    alert.rule_name,
                    alert.evidence,
                    alert.description,
                    alert.suggestion,
                    alert.packet_id,
                    json.dumps(alert.extra,ensure_ascii=False)#这里置为False，允许非ASSIC字符出现，比如中文字符

                )

            )
    def _row_to_alert(self,row:sqlite3.Row)->Alert:
        alert=Alert(alert_id=row['alert_id'],timestamp=row['timestamp'],category=AttackCategory(row['category']),
                    level=AlertLevel(row['level']),src_ip=row['src_ip'],dst_ip=row['dst_ip'],
                    src_port=row['src_port'],dst_port=row['dst_port'],protocol=Protocol(row['protocol']),
                    rule_id=row['rule_id'],rule_name=row['rule_name'],evidence=row['evidence'],
                    description=row['description'],suggestion=row['suggestion'] or "",packet_id=row['packet_id'],
                    extra=json.loads(row['extra_json'] or "{}")
                    )
        return alert

    def list_recent(self,limit:int=100)->list[Alert]:
        with self.database.connect() as conn:
            cursor=conn.execute(
                """
                select *
                from alerts
                order by timestamp DESC
                limit ?
                """,
                (limit,)#这里加逗号是为了将这一项识别为一个元组，execute语句的第二个参数需要是一个列表或元组
            ).fetchall()
        
        result=[]
        
        for row in cursor:
            result.append(self._row_to_alert(row))

        return result     


    def list_all(self)->list[Alert]:
        with self.database.connect() as conn:
            cursor=conn.execute(
                """
                select *
                from alerts
                order by timestamp
                """
                ).fetchall()
        
        result=[]
        
        for row in cursor:
            result.append(self._row_to_alert(row))
        
        return result
    


    def find_by_id(self,alert_id:str)->Alert|None:
        with self.database.connect() as conn:
            cursor=conn.execute(
                """
                select *
                from alerts
                where alert_id= ?
                """,
                (alert_id,)
            ).fetchone()
        if cursor==None:
            return None
        return self._row_to_alert(cursor) 




 




