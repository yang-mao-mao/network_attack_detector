from ..core.models import PacketInfo,Protocol
from .database import Database
import sqlite3




class PacketRepository():
    
    def __init__(self,database:Database)->None:
        self.database=database
    
    def save(self,Packet:PacketInfo)->None:
        with self.database.connect() as conn:
            conn.execute(
                """
                insert or replace into packets
                (packet_id,timestamp,src_ip,dst_ip,src_port,dst_port,
                protocol,length,payload_preview,raw_summary) 
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    Packet.packet_id,
                    Packet.timestamp,
                    Packet.src_ip,
                    Packet.dst_ip,
                    Packet.src_port,
                    Packet.dst_port,
                    Packet.protocol.value,
                    Packet.length,
                    Packet.payload_text,
                    Packet.raw_summary,
                )

            )

    def _row_to_packet(self,row:sqlite3.Row)->PacketInfo:
        packet=PacketInfo(
            packet_id=row['packet_id'],
            timestamp=row['timestamp'],
            src_ip=row['src_ip'],
            dst_ip=row['dst_ip'],
            src_port=row['src_port'],
            dst_port=row['dst_port'],
            protocol=Protocol(row['protocol']),
            length=row['length'],
            payload_text=row['payload_preview'],
            raw_summary=row['raw_summary']
        )
        return packet
    
    def list_recent(self,limit:int=100)->list[PacketInfo]:
        with self.database.connect() as conn:
            cursor=conn.execute(
                """
                select *
                from packets
                order by timestamp DESC
                limit ?
                """,
                (limit,)
            ).fetchall()

        result=[]
        for row in cursor:
            result.append(self._row_to_packet(row))
        
        return result


    def list_all(self)->list[PacketInfo]:
        with self.database.connect() as conn:
            cursor=conn.execute(
                """
                select *
                from packets
                """
            ).fetchall()
        
        result=[]

        for row in cursor:
            result.append(self._row_to_packet(row))

        return result


    def find_by_id(self,packet_id:str)->PacketInfo|None:
        with self.database.connect() as conn:
            cursor=conn.execute(
                """
                select *
                from packets
                where packet_id= ?
                """,
                (packet_id,)
            ).fetchone()
        if cursor==None:
            return None
        result=self._row_to_packet(cursor)
        return result

