"""Source package for the network attack detector."""

__all__ = ["core", "storage", "utils"]
#这一行代码更像是一个说明，说明这个项目对外可公开的文件有哪些，其他文件尽量不要调用（真调用也是可以的）
#一个包的__init__.py文件，当导入这个包的时候，里面的代码会被执行，当然，这里并没有可实际执行的代码，all只是声明，并不会导入这三个模块