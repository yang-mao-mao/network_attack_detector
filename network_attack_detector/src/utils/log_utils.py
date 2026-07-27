# from __future__ import annotations
# from pathlib import Path
# import logging
# import logging.config 

# import copy
# from .file_utils import read_yaml,resolve_path,ensure_parent_dir

# #设置默认的日志格式
# DEFAULT_LOG_FORMAT="%(asctime)s|%(levelname)s|%(name)s|%(message)s"

# #接受两个参数，配置文件路径和项目根目录路径
# def setup_logging(config_path:Path|str|None=None,project_root:Path|str|None=None):
#     #假如没有传入配置文件的路径，那么就利用basicconfig配置一个最小托底的日志程序（级别，格式）
#     if config_path is None:
#         logging.basicConfig(level=logging.INFO,format=DEFAULT_LOG_FORMAT)
#         return
    
#     #假设传入了一个路径，根据这个路径获取配置信息
#     path=Path(config_path)
#     config=read_yaml(path)
    
#     #检查config对象是不是字典
#     if not isinstance(config,dict):
#         raise ValueError(f"Logging config must be a mapping : {path}")
    
#     #根据项目根目录路径是否存在选择不同的操作
#     root=Path(project_root) if project_root is not None else Path(path.resolve().parents[1])
#     #将config对象里面的相对地址都改为绝对地址,并且要在磁盘上创建父目录
#     prepared_config=_prepare_logging_config(config,root)  
#     logging.config.dictConfig(prepared_config)
      
    

# def _prepare_logging_config(config:dict,root:Path|str):
#     prepared=copy.deepcopy(config)
#     handlers=prepared.get('handlers',{})
    
#     for handler in handlers.values():
#         if not isinstance(handler,dict):
#             continue
#         filename=handler.get('filename')
#         if not filename:
#             continue
#         prepared_path=resolve_path(root,filename)
#         ensure_parent_dir(prepared_path)
#         handler['filename']=str(prepared_path)
    
#     return prepared
        
# def get_logger(name: str | None = None) -> logging.Logger:
#     """Return a logger using the project's configured logging settings."""
#     return logging.getLogger(name)

import logging
import logging.config
from pathlib import Path
from .file_utils import read_yaml,resolve_path,ensure_parent_dir
import copy

DEFAULT_LOGGER_FORMAT='%(asctime)s|%(filename)s|%(levelname)s|%(message)s'
#传入两个路径
def setup_logging(config_path:str|Path|None=None,project_root:str|Path|None=None):
    #首先检查配置文件路径是否存在，假设不存在，搞一个默认的日志记录器
    if config_path is None:
        logging.basicConfig(level=logging.INFO,format=DEFAULT_LOGGER_FORMAT)
        return
    
    configpath=Path(config_path)
    #去读取配置文件，并将其转化为python对象
    config=read_yaml(configpath)
    
    #检查config是不是dict类型的对象
    if not isinstance(config,dict):
        raise ValueError(f"config must be a dict:{configpath}")
    
    #将配置文件里的相对路径改为绝对路径
    root=Path(project_root) if project_root is not None else configpath.resolve().parents[1]
    
    prepared_config=_prepare_logging_config(config,root)
    
    logging.config.dictConfig(prepared_config)



def get_logger(name:str|None=None):
    return logging.getLogger(name)


def _prepare_logging_config(config:dict,root:Path):
    prepared_config=copy.deepcopy(config)
    handlers=prepared_config.get('handlers',{})
    for handler in handlers.values():
        if not isinstance(handler,dict):
            continue
        filename=handler.get('filename')
        if not filename:
            continue
        prepared_path=resolve_path(root,filename)
        ensure_parent_dir(prepared_path)
        handler['filename']=str(prepared_path)
        
    return prepared_config
        
    
    