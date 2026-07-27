# import yaml
# from pathlib import Path
# #根据传入的路径，打开配置文件，并且返回一个python中的对象
# def read_yaml(path:Path|str):
#     with Path(path).open("r",encoding="utf-8") as file:
#         return yaml.safe_load(file)
    
# #传入根目录地址(可能相对可能绝对)和相对路径,返回目标文件的绝对地址
# def resolve_path(base_dir:str|Path,path:str|Path):
#     target=Path(path)
#     if target.is_absolute():
#         return target
#     return (Path(Path(base_dir)/target)).resolve()   

# #传入一个path类的对象，确保父目录存在,返回父目录的Path对象
# def ensure_parent_dir(x:Path|str):
#     path=Path(x)
#     path.parent.mkdir(parents=True,exist_ok=True)
#     return path.parent

from pathlib import Path
import yaml


#传入一个yaml文件的所在路径，然后返回一个python对象
def read_yaml(yaml_path:str|Path):
    path=Path(yaml_path)
    with path.open("r",encoding="utf-8") as file:
        config=yaml.safe_load(file)
        return config
    

def resolve_path(base_dir:str|Path,x:str|Path):
    root=Path(base_dir).resolve()
    filename=Path(x)
    if filename.is_absolute():
        return filename
    return Path(root/filename)

def ensure_parent_dir(x:str|Path):
    path=Path(x).resolve()
    path.parent.mkdir(parents=True,exist_ok=True)
    return path.parent
    