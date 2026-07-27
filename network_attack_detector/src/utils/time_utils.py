from __future__ import annotations
import time
import datetime

DEFAULT_DATETIME_FORMAT="%Y-%m-%d %H:%M:%S"

#要实现什么方法：
#返回当前时间戳,以秒为单位
def now_ts():
    time_stamp=time.time()
    return time_stamp

#返回当前时间戳，以毫秒为单位
def now_ms():
    time_stamp=int(time.time()*1000)#一般毫秒级时间戳都是使用int类型
    return time_stamp

#将时间戳转换为时间对象再转换为时间字符串
def format_ts(time_stamp:float,format:str=DEFAULT_DATETIME_FORMAT):
    return time.strftime(format,time.localtime(time_stamp))

#将时间字符串转换为时间戳
def parse_ts(time_str:str,format:str=DEFAULT_DATETIME_FORMAT):
    return time.mktime(time.strptime(time_str,format))

#快捷获取当前时间（时间字符串形式）
def current_time_str(format:str=DEFAULT_DATETIME_FORMAT):
    return format_ts(time.time(),format)
