"""
主程序模块
"""


class Demo:
    """示例类"""

    def __init__(self, name: str = "Demo"):
        """
        初始化Demo类

        Args:
            name: 实例名称
        """
        self.name = name

    def greet(self) -> str:
        """
        返回问候语

        Returns:
            str: 问候信息
        """
        return f"你好，我是 {self.name}"

    def process(self, data: any) -> any:
        """
        处理数据的方法

        Args:
            data: 待处理的数据

        Returns:
            处理后的数据
        """
        # 在这里添加你的业务逻辑
        return data


if __name__ == "__main__":
    demo = Demo("测试实例")
    print(demo.greet())

