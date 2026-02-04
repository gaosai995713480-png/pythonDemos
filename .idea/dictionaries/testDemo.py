class Demo:
    def __init__(self, name):
        self.name = name

    def greet(self):
        return f"你好，我是{self.name}"


if __name__ == "__main__":
    demo = Demo("测试实例")
    print(demo.greet())

if __name__ == "__main__":
    Demo("dsada").greet()
    Demo("dsada").greet()